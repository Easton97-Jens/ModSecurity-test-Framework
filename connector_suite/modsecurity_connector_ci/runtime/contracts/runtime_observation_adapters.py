#!/usr/bin/env python3
"""Adapters for the canonical runtime-observation contract.

Adapters are deliberately mechanical. They accept only structured facts that
the connector harness already established and never turn an evidence digest,
request shape, or command exit status into a PASS result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from modsecurity_connector_ci.runtime.contracts.runtime_observation import SCHEMA_VERSION, RuntimeObservationError, adapter_for as contract_adapter_for, evidence_manifest_digest, read_bounded_evidence_file


PRODUCER_VERSION = "1.0.0"
STRUCTURED_CONNECTORS = frozenset(("envoy", "lighttpd", "traefik"))


class ProducerEvidenceUnavailable(RuntimeError):
    """Raised when an adapter lacks separately produced live evidence."""


@dataclass(frozen=True)
class StructuredObservationInput:
    """Typed input boundary for facts established by a connector producer.

    Values intentionally remain nullable where absence is meaningful: a
    missing observation is emitted as a non-PASS disposition, never filled in
    from a request, a fixture, or an evidence digest.
    """

    connector: str
    adapter_id: str
    integration_mode: str
    run_id: str
    parent_commit: str
    framework_commit: str
    mrts_commit: str
    config_test_status: str | None
    host_start_status: str | None
    reachability_status: str | None
    allow_expected_status: int
    allow_observed_status: int | None
    block_expected_status: int
    block_observed_status: int | None
    bypass_expected_status: int
    bypass_observed_status: int | None
    expected_action: str
    observed_action: str | None
    expected_trigger_rule_ids: list[int]
    observed_trigger_rule_ids: list[int] | None
    expected_intervention_rule_ids: list[int]
    observed_intervention_rule_ids: list[int] | None
    framework_execution_status: str | None
    framework_validation_status: str | None
    framework_cases: list[Mapping[str, Any]]
    cleanup_status: str | None
    cleanup: Mapping[str, int]
    isolation: Mapping[str, bool]
    evidence: list[Mapping[str, str]]
    evidence_root: Path | str
    manifest_digest: str
    fixture_id: str = "crs_sqli_anomaly_block"
    source_contract: str = "five-connectors-with-crs-no-mrts"


@dataclass(frozen=True)
class RuntimeObservationAdapter:
    """A closed adapter identity and its independently available producer."""

    connector: str
    adapter_id: str
    integration_mode: str
    producer: str | None
    producer_available: bool
    protected_separate: bool

    def require_producer_evidence(self) -> None:
        if not self.producer_available:
            raise ProducerEvidenceUnavailable(
                f"{self.adapter_id} has no approved structured live runtime producer"
            )


def adapter_for(
    connector: str, adapter_id: str, integration_mode: str
) -> RuntimeObservationAdapter:
    """Resolve exactly one catalogued adapter identity, never a fallback."""
    try:
        contract_adapter = contract_adapter_for(connector, adapter_id, integration_mode)
    except RuntimeObservationError as exc:
        raise ValueError("connector adapter identity is not supported") from exc
    return RuntimeObservationAdapter(
        connector=contract_adapter.connector,
        adapter_id=contract_adapter.adapter_id,
        integration_mode=contract_adapter.integration_mode,
        producer=contract_adapter.producer,
        producer_available=contract_adapter.live_producer_supported,
        protected_separate=contract_adapter.protected_separate,
    )


def _assertion(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    """Emit one assertion without manufacturing a result from absent data."""
    if observed is None:
        return {
            "required": True,
            "applicable": True,
            "executed": False,
            "live_executed": False,
            "expected": dict(expected),
            "observed": {},
            "result": "NOT_EXECUTED",
            "reason": f"{reason}: structured observation is missing",
            "evidence_kind": "structured_connector_evidence",
        }
    result = "PASS" if dict(expected) == dict(observed) else "FAIL"
    return {
        "required": True,
        "applicable": True,
        "executed": True,
        "live_executed": True,
        "expected": dict(expected),
        "observed": dict(observed),
        "result": result,
        "reason": reason if result == "PASS" else f"{reason}: expected and observed facts disagree",
        "evidence_kind": "structured_connector_evidence",
    }


def _safe_evidence_records(
    evidence_root: Path | str, evidence: list[Mapping[str, str]]
) -> list[dict[str, str]]:
    """Recompute inventory digests through the descriptor-pinned read path.

    The digest authenticates the referenced structured record. It is not an
    observation and is never used to infer an assertion or Framework result.
    """
    records: list[dict[str, str]] = []
    for record in evidence:
        name = str(record["name"])
        path = str(record["path"])
        data = read_bounded_evidence_file(
            Path(evidence_root) / path,
            evidence_root,
            label=f"{name} adapter evidence",
        )
        digest = hashlib.sha256(data).hexdigest()
        supplied_digest = record.get("sha256")
        if supplied_digest is not None and supplied_digest != digest:
            raise ProducerEvidenceUnavailable("adapter evidence digest changed before normalization")
        records.append(
            {
                "name": name,
                "path": path,
                "sha256": digest,
                "kind": "structured_connector_evidence",
            }
        )
    return records


def _status_observation(value: str | None) -> dict[str, str] | None:
    return None if value is None else {"status": value}


def _status_assertion(expected_status: str, observed_status: str | None, reason: str) -> dict[str, Any]:
    return _assertion({"status": expected_status}, _status_observation(observed_status), reason)


def _status_code_observation(value: int | None) -> dict[str, int] | None:
    return None if value is None else {"http_status": value}


def _copy_framework_cases(cases: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Copy caller-owned prevalidated records without inferring their outcome."""
    return [dict(case) for case in cases]


def _framework_counts(cases: list[Mapping[str, Any]]) -> dict[str, int]:
    counts = {
        "selected_count": 0,
        "executed_count": 0,
        "passed_count": 0,
        "failed_count": 0,
        "cancelled_count": 0,
        "unsupported_count": 0,
        "not_applicable_count": 0,
        "not_executed_count": 0,
        "failure_count": 0,
        "mismatch_count": 0,
    }
    result_to_count = {
        "PASS": "passed_count",
        "FAIL": "failed_count",
        "CANCELLED": "cancelled_count",
        "UNSUPPORTED": "unsupported_count",
        "NOT_APPLICABLE": "not_applicable_count",
        "NOT_EXECUTED": "not_executed_count",
    }
    for case in cases:
        if case.get("selected") is True:
            counts["selected_count"] += 1
        if case.get("executed") is True:
            counts["executed_count"] += 1
        count_name = result_to_count.get(case.get("result"))
        if count_name is not None:
            counts[count_name] += 1
        for field in ("failure_count", "mismatch_count"):
            value = case.get(field)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                counts[field] += value
    return counts


def _framework_aggregate(request: StructuredObservationInput) -> dict[str, Any]:
    cases = _copy_framework_cases(request.framework_cases)
    counts = _framework_counts(cases)
    return {
        "selection_status": "SELECTED" if counts["selected_count"] else "NONE_SELECTED",
        "execution_status": request.framework_execution_status or "NOT_RUN",
        "validation_status": request.framework_validation_status or "PARTIAL",
        **counts,
        "cases": cases,
    }


def _runtime_status(
    assertions: list[Mapping[str, Any]], framework: Mapping[str, Any], cleanup_status: str
) -> str:
    if any(assertion.get("result") == "FAIL" for assertion in assertions):
        return "VALIDATION_FAILED"
    if framework.get("failed_count", 0) or framework.get("mismatch_count", 0):
        return "VALIDATION_FAILED"
    if cleanup_status == "FAIL":
        return "FAIL"
    required_pass = all(assertion.get("result") == "PASS" for assertion in assertions)
    framework_pass = (
        framework.get("selection_status") == "SELECTED"
        and framework.get("execution_status") == "RUN"
        and framework.get("validation_status") == "CONTRACT_VALIDATED"
        and framework.get("selected_count") == framework.get("executed_count") == framework.get("passed_count")
        and framework.get("failure_count") == 0
        and framework.get("mismatch_count") == 0
    )
    return "PASS" if required_pass and framework_pass and cleanup_status == "PASS" else "PARTIAL"


def build_structured_observation(request: StructuredObservationInput) -> dict[str, Any]:
    """Build a canonical observation from explicit host and Framework facts.

    Apache and both HAProxy paths remain unavailable here until each has an
    independent producer. The protected NGINX broker is intentionally not
    routed through this generic adapter.
    """
    adapter = adapter_for(request.connector, request.adapter_id, request.integration_mode)
    adapter.require_producer_evidence()
    if request.connector not in STRUCTURED_CONNECTORS or adapter.protected_separate:
        raise AssertionError("finite adapter catalog admitted an unsupported structured producer")
    if adapter.producer is None:
        raise AssertionError("structured adapter lacks its catalogued producer")
    evidence_records = _safe_evidence_records(request.evidence_root, request.evidence)
    evidence_digest = evidence_manifest_digest(evidence_records)
    mapped_isolation = {
        "mrts_runner_invoked": request.isolation.get("runner_invoked"),
        "mrts_inventory_loaded": request.isolation.get("case_inventory_loaded"),
        "mrts_process_started": request.isolation.get("process_started"),
        "mrts_listener_created": request.isolation.get("socket_or_listener_created"),
        "mrts_artifact_used": request.isolation.get("artifact_used"),
    }
    cleanup_status = request.cleanup_status or "PARTIAL"
    mapped_cleanup = {
        "host_processes_remaining": request.cleanup.get("host_processes_remaining"),
        "helper_processes_remaining": request.cleanup.get("helper_processes_remaining"),
        "listeners_remaining": request.cleanup.get("listeners_remaining"),
        "sockets_remaining": request.cleanup.get("sockets_remaining"),
        "pid_files_remaining": request.cleanup.get("pid_files_remaining"),
        "temporary_paths_remaining": request.cleanup.get("temporary_paths_remaining"),
        "cleanup_status": cleanup_status,
    }
    block_expected = {
        "http_status": request.block_expected_status,
        "action": request.expected_action,
        "rule_ids": list(request.expected_trigger_rule_ids),
        "intervention_rule_ids": list(request.expected_intervention_rule_ids),
    }
    block_observed = (
        None
        if (
            request.block_observed_status is None
            or request.observed_action is None
            or request.observed_trigger_rule_ids is None
            or request.observed_intervention_rule_ids is None
        )
        else {
            "http_status": request.block_observed_status,
            "action": request.observed_action,
            "rule_ids": list(request.observed_trigger_rule_ids),
            "intervention_rule_ids": list(request.observed_intervention_rule_ids),
        }
    )
    assertions = [
        _status_assertion("PASS", request.config_test_status, "host configuration test"),
        _status_assertion("PASS", request.host_start_status, "host start"),
        _status_assertion("PASS", request.reachability_status, "host reachability"),
        _assertion(
            {"http_status": request.allow_expected_status},
            _status_code_observation(request.allow_observed_status),
            "allow control",
        ),
        _assertion(block_expected, block_observed, "CRS intervention"),
        _assertion(
            {"http_status": request.bypass_expected_status, "action": request.expected_action},
            None
            if request.bypass_observed_status is None or request.observed_action is None
            else {
                "http_status": request.bypass_observed_status,
                "action": request.observed_action,
            },
            "bypass control",
        ),
    ]
    framework = _framework_aggregate(request)
    return {
        "schema_version": SCHEMA_VERSION,
        "identity": {
            "connector": adapter.connector,
            "adapter_id": adapter.adapter_id,
            "integration_mode": adapter.integration_mode,
            "profile": "with-crs-no-mrts",
            "crs": True,
            "mrts": False,
            "run_id": request.run_id,
            "parent_commit": request.parent_commit,
            "framework_commit": request.framework_commit,
            "mrts_commit": request.mrts_commit,
            "producer": adapter.producer,
            "producer_version": PRODUCER_VERSION,
        },
        "runtime": {
            "config_test": assertions[0],
            "host_start": assertions[1],
            "reachability": assertions[2],
            "allow_case": assertions[3],
            "block_case": assertions[4],
            "bypass_case": assertions[5],
            "runtime_status": _runtime_status(assertions, framework, cleanup_status),
        },
        "framework": framework,
        "isolation": mapped_isolation,
        "cleanup": mapped_cleanup,
        "provenance": {
            "evidence_kind": "structured_connector_evidence",
            "fixture_id": request.fixture_id,
            "source_contract": request.source_contract,
            "manifest_digest": request.manifest_digest,
            "evidence_digest": evidence_digest,
            "validation_basis": "evidence-digest-v1",
            "contract_schema_version": SCHEMA_VERSION,
            "producer_version": PRODUCER_VERSION,
            "evidence": evidence_records,
        },
    }


def canonical_fixture_digest(label: str) -> str:
    """Return a deterministic fixture manifest digest without host evidence."""
    return hashlib.sha256(label.encode("ascii")).hexdigest()
