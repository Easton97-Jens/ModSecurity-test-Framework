"""Python mirror of the C-first msconnector metadata model.

The smoke harnesses intentionally do not use C FFI. This module keeps Python
summary JSON schema-compatible with the common C helper concepts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

RESULT_STATUSES = ("pass", "fail", "blocked", "skipped", "xfail")
IMPORT_STATUS_KEYS = (
    "fully_imported_common",
    "connector_specific",
    "mapped_only",
    "blocked",
    "xfail",
    "v2_imported",
    "v3_imported",
)
STATUS_MODEL = "msconnector_status"
ORIGIN_MODEL = "msconnector_origin"
INTERVENTION_MODEL = "msconnector_intervention"

OPERATION_STATUSES = {
    "pass": "ok",
    "fail": "error",
    "blocked": "blocked",
    "skipped": "unsupported",
    "xfail": "unsupported",
}

VARIABLE_CAPABILITIES = {
    "ARGS": {"query-args", "form-urlencoded"},
    "ARGS_NAMES": {"args-names"},
    "REQUEST_COOKIES": {"request-cookies"},
    "REQUEST_HEADERS": {"request-headers"},
    "REQUEST_URI": {"request-uri"},
    "REQUEST_BODY": {"request-body", "json", "body-processors"},
    "FILES": {"files"},
    "XML": {"xml"},
    "AUDIT_LOG": {"audit-log"},
    "RESPONSE_HEADERS": {"response-headers"},
}


def operation_status(result_status: str) -> str:
    return OPERATION_STATUSES.get(result_status, "error")


def intervention_metadata(
    expected_intervention: str,
    expected_status: int,
    log_message: str = "",
) -> dict[str, object]:
    disruptive = expected_intervention in {"deny", "block", "redirect"}
    return {
        "disruptive": disruptive,
        "status": expected_status if disruptive else 0,
        "log_message": log_message,
    }


def intervention_from_expect(expect: Mapping[str, object]) -> dict[str, object]:
    return intervention_metadata(
        str(expect.get("intervention", "")),
        int(expect["status"]),
        str(expect.get("log_message", "")),
    )


def origin_metadata(
    source: str = "",
    source_repo: str = "",
    source_url: str = "",
    source_commit: str = "",
    source_version: str = "",
    license_name: str = "",
    imported_path: str = "",
) -> dict[str, str]:
    return {
        "source": source,
        "source_repo": source_repo,
        "source_url": source_url,
        "source_commit": source_commit,
        "source_version": source_version,
        "license": license_name,
        "imported_path": imported_path,
    }


def passing_capability_sets(entries: list[dict[str, object]]) -> list[set[str]]:
    sets = []
    for entry in entries:
        if str(entry.get("status", "")) != "pass":
            continue
        capabilities = entry.get("capabilities", [])
        if isinstance(capabilities, list):
            sets.append({str(item) for item in capabilities})
    return sets


def verified_variables(entries: list[dict[str, object]]) -> list[str]:
    variables = []
    for names in passing_capability_sets(entries):
        for variable, capabilities in VARIABLE_CAPABILITIES.items():
            if names.intersection(capabilities):
                variables.append(variable)
    return sorted(dict.fromkeys(variables))


def result_counts(entries: list[dict[str, object]]) -> dict[str, int]:
    counts = dict.fromkeys(RESULT_STATUSES, 0)
    for entry in entries:
        status = str(entry.get("status", "fail"))
        counts.setdefault(status, 0)
        counts[status] += 1
    return counts


def import_status_counts(path: str | None) -> dict[str, int]:
    if not path:
        return {}
    import_status_path = Path(path)
    if not import_status_path.exists():
        return {}
    manifest = json.loads(import_status_path.read_text(encoding="utf-8"))
    return {
        key: len(manifest.get(key, []))
        for key in IMPORT_STATUS_KEYS
        if isinstance(manifest.get(key, []), list)
    }


def audit_behavior(entries: list[dict[str, object]], import_status: dict[str, int]) -> str:
    for entry in entries:
        capabilities = entry.get("capabilities", [])
        if str(entry.get("status", "")) == "fail" and isinstance(capabilities, list):
            if {"audit-log", "audit-log-absent"}.intersection({str(item) for item in capabilities}):
                return "unexpected"
    if import_status.get("xfail", 0):
        return "unstable"
    return "stable"


def default_environment() -> str:
    configured = os.environ.get("SMOKE_ENVIRONMENT", "").strip()
    if configured:
        return configured
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        return "github-actions"
    return "local"


def connector_summary(
    *,
    connector: str,
    entries: list[dict[str, object]],
    import_status_file: str | None = None,
    connector_path: str = "real-world",
    validation_mode: str = "real-world-connector-path",
    environment: str | None = None,
    server: str = "",
    server_binary: str = "",
    module: str = "",
    libmodsecurity: str = "",
    origin_source: str = "",
    origin_source_repo: str = "",
    origin_source_url: str = "",
    origin_source_commit: str = "",
    origin_source_version: str = "",
    origin_license: str = "",
    origin_imported_path: str = "",
) -> dict[str, object]:
    cases = {str(entry.get("name", "")): entry for entry in entries}
    import_status = import_status_counts(import_status_file)
    summary: dict[str, object] = {
        "status_model": STATUS_MODEL,
        "origin_model": ORIGIN_MODEL,
        "intervention_model": INTERVENTION_MODEL,
        "connector_path": connector_path,
        "validation_mode": validation_mode,
        "environment": environment or default_environment(),
        "audit_behavior": audit_behavior(entries, import_status),
        "server": server or connector,
        "server_binary": server_binary,
        "module": module,
        "libmodsecurity": libmodsecurity,
        "origin": origin_metadata(
            origin_source,
            origin_source_repo,
            origin_source_url,
            origin_source_commit,
            origin_source_version,
            origin_license,
            origin_imported_path,
        ),
        "verified_variables": verified_variables(entries),
        "summary": result_counts(entries),
        "cases": cases,
    }
    if import_status:
        summary["import_status"] = import_status
    return summary


def empty_connector_summary(
    *,
    connector: str,
    status: str,
    connector_path: str = "real-world",
    validation_mode: str = "real-world-connector-path",
    environment: str | None = None,
    server: str = "",
    server_binary: str = "",
    module: str = "",
    libmodsecurity: str = "",
    origin_source: str = "",
    origin_source_repo: str = "",
    origin_source_url: str = "",
    origin_source_commit: str = "",
    origin_source_version: str = "",
    origin_license: str = "",
    origin_imported_path: str = "",
) -> dict[str, object]:
    counts = dict.fromkeys(RESULT_STATUSES, 0)
    counts.setdefault(status, 0)
    counts[status] += 1
    return {
        "audit_behavior": "unstable",
        "build": status,
        "connector_path": connector_path,
        "environment": environment or default_environment(),
        "intervention_model": INTERVENTION_MODEL,
        "origin_model": ORIGIN_MODEL,
        "validation_mode": validation_mode,
        "status_model": STATUS_MODEL,
        "server": server or connector,
        "server_binary": server_binary,
        "module": module,
        "libmodsecurity": libmodsecurity,
        "origin": origin_metadata(
            origin_source,
            origin_source_repo,
            origin_source_url,
            origin_source_commit,
            origin_source_version,
            origin_license,
            origin_imported_path,
        ),
        "verified_variables": [],
        "summary": counts,
        "cases": {},
    }
