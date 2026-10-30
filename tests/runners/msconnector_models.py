"""Python mirror of the C-first msconnector metadata model.

The smoke harnesses intentionally do not use C FFI. This module keeps Python
summary JSON schema-compatible with the common C helper concepts.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Mapping

from modsecurity_test_framework.result_identity import (
    RESULT_BINDING_FIELDS,
    validate_result_binding,
    validate_result_context,
    validate_summary_identity,
    validate_request_observation,
)

RESULT_STATUSES = ("pass", "fail", "blocked", "not_executable", "skipped")
IMPORT_STATUS_KEYS = (
    "fully_imported_common",
    "connector_specific",
    "mapped_only",
    "blocked",
    "former_xfail",
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
    "not_executable": "unsupported",
    "skipped": "unsupported",
}

VARIABLE_CAPABILITIES = {
    "ARGS": {"query-args", "form-urlencoded"},
    "ARGS_NAMES": {"args-names"},
    "REQUEST_COOKIES": {"request-cookies"},
    "REQUEST_COOKIES_NAMES": {"request-cookies"},
    "REQUEST_HEADERS": {"request-headers"},
    "REQUEST_HEADERS_NAMES": {"request-headers"},
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


NON_PROMOTABLE_CLASSIFICATIONS = {"pending", "future", "connector_gap", "connector-gap", "runtime_difference", "runtime-difference", "non-promoted", "non_promoted"}


def is_verified_runtime_pass(entry: dict[str, object]) -> bool:
    if str(entry.get("status", "")).strip().lower() != "pass":
        return False
    if entry.get("live_executed") is not True:
        return False
    try:
        validate_result_binding(entry)
    except ValueError:
        return False
    if entry.get("runtime_verified") is False or entry.get("promotion_allowed") is False:
        return False
    if entry.get("response_body_non_verified") is True or entry.get("strict_abort") is True:
        return False
    classification = str(entry.get("runtime_classification") or entry.get("metadata_classification") or "active").strip().lower()
    if classification in NON_PROMOTABLE_CLASSIFICATIONS:
        return False
    return True


def passing_capability_sets(entries: list[dict[str, object]]) -> list[set[str]]:
    sets = []
    for entry in entries:
        if not is_verified_runtime_pass(entry):
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
        if status == "xfail":
            status = "fail"
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


def audit_behavior(entries: list[dict[str, object]]) -> str:
    for entry in entries:
        capabilities = entry.get("capabilities", [])
        if str(entry.get("status", "")) == "fail" and isinstance(capabilities, list):
            if {"audit-log", "audit-log-absent"}.intersection({str(item) for item in capabilities}):
                return "unexpected"
    return "stable"


def default_environment() -> str:
    configured = os.environ.get("SMOKE_ENVIRONMENT", "").strip()
    if configured:
        return configured
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        return "github-actions"
    return "local"


@dataclass(frozen=True)
class SummaryContext:
    connector_path: str = "real-world"
    validation_mode: str = "real-world-connector-path"
    environment: str | None = None
    server: str = ""
    server_binary: str = ""
    module: str = ""
    libmodsecurity: str = ""
    origin_source: str = ""
    origin_source_repo: str = ""
    origin_source_url: str = ""
    origin_source_commit: str = ""
    origin_source_version: str = ""
    origin_license: str = ""
    origin_imported_path: str = ""
    run_id: str = ""
    source_revision: str = ""

    def resolved_environment(self) -> str:
        return self.environment or default_environment()

    def resolved_server(self, connector: str) -> str:
        return self.server or connector

    def origin(self) -> dict[str, str]:
        return origin_metadata(
            self.origin_source,
            self.origin_source_repo,
            self.origin_source_url,
            self.origin_source_commit,
            self.origin_source_version,
            self.origin_license,
            self.origin_imported_path,
        )


def _normalize_summary_entry(entry):
    normalized = dict(entry)
    if str(normalized.get("status", "")) == "xfail":
        normalized["status"] = "fail"
    if str(normalized.get("status", "")) not in RESULT_STATUSES:
        raise ValueError("case result has an unknown status")
    if normalized.get("evidence_identity") == "request_bound":
        normalized.update(validate_request_observation(normalized))
    elif any(
        normalized.get(field) for field in RESULT_BINDING_FIELDS if field != "case_id"
    ):
        if normalized["status"] != "pass" and not normalized.get("transaction_id"):
            normalized.update(validate_result_context(normalized))
            normalized["promotion_allowed"] = False
        else:
            normalized.update(validate_result_binding(normalized))
    else:
        normalized["promotion_allowed"] = False
    return normalized


def _summary_evidence_identity(all_bound, normalized_entries):
    if all_bound:
        return "bound"
    if normalized_entries and all(
        entry.get("evidence_identity") == "request_bound"
        for entry in normalized_entries
    ):
        return "request_bound"
    if any(entry.get("transaction_id") for entry in normalized_entries):
        return "mixed"
    return "unbound"


def connector_summary(
    *,
    connector: str,
    entries: list[dict[str, object]],
    import_status_file: str | None = None,
    context: SummaryContext | None = None,
) -> dict[str, object]:
    summary_context = context or SummaryContext()
    normalized_entries = []
    for entry in entries:
        normalized_entries.append(_normalize_summary_entry(entry))
    identity, all_bound = summary_bundle_identity(normalized_entries, summary_context)
    if not all_bound:
        for normalized in normalized_entries:
            normalized["promotion_allowed"] = False
    cases = distinct_case_results(normalized_entries)
    distinct_entries = list(cases.values())
    import_status = import_status_counts(import_status_file)
    summary: dict[str, object] = {
        "status_model": STATUS_MODEL,
        "origin_model": ORIGIN_MODEL,
        "intervention_model": INTERVENTION_MODEL,
        "connector_path": summary_context.connector_path,
        "validation_mode": summary_context.validation_mode,
        "environment": summary_context.resolved_environment(),
        "audit_behavior": audit_behavior(distinct_entries),
        "server": summary_context.resolved_server(connector),
        "server_binary": summary_context.server_binary,
        "module": summary_context.module,
        "libmodsecurity": summary_context.libmodsecurity,
        "origin": summary_context.origin(),
        "verified_variables": verified_variables(distinct_entries),
        "summary": result_counts(distinct_entries),
        "cases": cases,
        "attempted": len(normalized_entries),
        "total_cases": len(cases),
        "attempts": normalized_entries,
        "run_id": identity.get("run_id", ""),
        "source_revision": identity.get("source_revision", ""),
        "evidence_identity": _summary_evidence_identity(all_bound, normalized_entries),
        "promotion_allowed": all_bound
        and all(
            entry.get("promotion_allowed") is not False for entry in normalized_entries
        ),
    }
    if import_status:
        summary["import_status"] = import_status
    return summary


def summary_bundle_identity(entries: list[dict[str, object]], context: SummaryContext) -> tuple[dict[str, str], bool]:
    """Require one run/revision across the whole bundle, including distinct cases."""
    expected = validate_summary_identity(context.run_id, context.source_revision)
    identities = {(entry["run_id"], entry["source_revision"]) for entry in entries
                  if entry.get("run_id") and entry.get("source_revision")}
    if len(identities) > 1:
        raise ValueError("summary mixes run or source revision identities")
    observed = {}
    if identities:
        run_id, revision = next(iter(identities))
        observed = validate_summary_identity(run_id, revision)
    for field, value in expected.items():
        if field in observed and observed[field] != value:
            raise ValueError(f"summary requested {field} identity does not match its rows")
    all_bound = bool(entries) and all(all(entry.get(field) for field in RESULT_BINDING_FIELDS) for entry in entries)
    return {**observed, **expected}, all_bound


def _record_case_identity(entry, identities):
    name = entry.get("case_id") or entry.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("case result requires a nonempty stable case identity")
    case_identity = (entry.get("run_id"), name, entry.get("source_revision"))
    if name in identities and identities[name] != case_identity:
        raise ValueError("conflicting run or source revision for one case identity")
    identities[name] = case_identity
    return name, case_identity


def _record_attempt_owners(entry, name, transaction_owners, request_owners):
    owner_checks = []
    if entry.get("request_id"):
        owner_checks.append(
            (
                request_owners,
                (entry["run_id"], entry["request_id"]),
                (name, entry.get("transaction_id"), entry["source_revision"]),
            )
        )
    if entry.get("transaction_id"):
        owner_checks.append(
            (
                transaction_owners,
                (entry["run_id"], entry["transaction_id"]),
                (name, entry["request_id"], entry["source_revision"]),
            )
        )
    for owners, identity, owner in owner_checks:
        if identity in owners and owners[identity] != owner:
            raise ValueError("conflicting request/transaction assignment across cases")
        owners[identity] = owner


def _record_case_observation(entry, case_identity, attempts, observed_fields):
    attempt = (*case_identity, entry.get("request_id"), entry.get("transaction_id"))
    observation = (
        *tuple(entry.get(field) for field in observed_fields),
        json.dumps(entry.get("request_observation"), sort_keys=True),
    )
    if attempt in attempts and attempts[attempt] != observation:
        raise ValueError(
            "conflicting observations for one request/transaction identity"
        )
    attempts[attempt] = observation


def distinct_case_results(
    entries: list[dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Keep attempts, reject contradictory observations, count each case once.

    Retries may change request/transaction IDs and results. They never erase a
    failed observed attempt. A single summary cannot combine different runs or
    source revisions under the same case name.
    """
    cases: dict[str, dict[str, object]] = {}
    identities: dict[str, tuple[object, ...]] = {}
    attempts: dict[tuple[object, ...], tuple[object, ...]] = {}
    transaction_owners: dict[tuple[object, ...], tuple[object, ...]] = {}
    request_owners: dict[tuple[object, ...], tuple[object, ...]] = {}
    severity = {"pass": 0, "skipped": 1, "not_executable": 2, "blocked": 3, "fail": 4}
    observed_fields = (
        "status",
        "actual_status",
        "http_status",
        "visible_http_status",
        "actual_action",
        "rule_id",
        "phase",
        "intervention_http_status",
    )
    for entry in entries:
        name, case_identity = _record_case_identity(entry, identities)
        _record_attempt_owners(entry, name, transaction_owners, request_owners)
        _record_case_observation(entry, case_identity, attempts, observed_fields)
        previous = cases.get(name)
        if (
            previous is None
            or severity[str(entry["status"])] > severity[str(previous["status"])]
        ):
            cases[name] = entry
    return cases


def empty_connector_summary(
    *,
    connector: str,
    status: str,
    context: SummaryContext | None = None,
) -> dict[str, object]:
    if status not in RESULT_STATUSES or status == "pass":
        raise ValueError("empty preparation results cannot report a passing case")
    summary_context = context or SummaryContext()
    counts = dict.fromkeys(RESULT_STATUSES, 0)
    counts.setdefault(status, 0)
    counts[status] += 1
    return {
        "audit_behavior": "stable",
        "build": status,
        "connector_path": summary_context.connector_path,
        "environment": summary_context.resolved_environment(),
        "intervention_model": INTERVENTION_MODEL,
        "origin_model": ORIGIN_MODEL,
        "validation_mode": summary_context.validation_mode,
        "status_model": STATUS_MODEL,
        "server": summary_context.resolved_server(connector),
        "server_binary": summary_context.server_binary,
        "module": summary_context.module,
        "libmodsecurity": summary_context.libmodsecurity,
        "origin": summary_context.origin(),
        "verified_variables": [],
        "summary": counts,
        "cases": {},
        **validate_summary_identity(summary_context.run_id, summary_context.source_revision),
        "evidence_identity": "not_executed",
        "promotion_allowed": False,
    }
