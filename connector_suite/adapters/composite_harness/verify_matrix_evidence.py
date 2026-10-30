#!/usr/bin/env python3
"""Verify one isolated, metadata-only composite observer event log.

The input event log is the raw JSONL emitted by ``compositeObserver``. This
tool does not transform, synthesize, or correlate records across cases. The
manifest selects one isolated case artifact; correlation is established only
by the one server-generated decision_id repeated by every raw observer event.
Request IDs, URI, address, order between cases, and timing are never used.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import datetime as _datetime
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

_REPOSITORY_ROOT = connector_root()
_CI_LIB = _REPOSITORY_ROOT / "ci" / "lib"

from modsecurity_connector_ci.lib.runtime_path_utils import PrivateRuntimeRoot, open_private_runtime_root

SCHEMA = "msc-composite-evidence/v1"
EVIDENCE_SCOPE = "lifecycle_only"
MAX_EVENT_LOG_BYTES = 256 * 1024
MAX_EVENT_LINE_BYTES = 16 * 1024
MAX_OBSERVATION_BYTES = 16 * 1024
PHASES = ("P1", "P2", "P3", "P4")
# `reservation` is a payload-free pre-admission lifecycle opener. It permits
# a private UDS reservation that ForwardAuth never receives to end with one
# accountable abort terminal, without pretending that a lease was issued or
# that P1/P2 occurred.
LIFECYCLE_PHASES = {"reservation", "lease", "claim", "request_host_action", "host_action", "neutral_outcome", "terminal"}
CASES = {
    # An allow control still traverses P3/P4 of the same retained transaction.
    # The case name identifies the selected request-side vector, not a reason
    # to omit later observer phases from the lifecycle receipt.
    "p1_allow": PHASES,
    "p1_deny": ("P1",),
    "p2_allow": PHASES,
    "p2_deny": ("P1", "P2"),
    "p2_oversize": ("P1", "P2"),
    "p3_deny": ("P1", "P2", "P3"),
    "p3_redirect": ("P1", "P2", "P3"),
    "p4_safe": PHASES,
    "p4_strict": PHASES,
    # Lease omission is a pre-admission fail-closed path. It has a payload-free
    # reservation opener and terminal cleanup, but deliberately no P1/P2
    # transaction evidence after ForwardAuth rejects the missing lease.
    "metadata_omitted": (),
    # Envoy ext_authz has already admitted P1/P2 before its response-only
    # ext_proc companion receives dynamic metadata. A missing forwarded
    # metadata namespace is a fail-closed response-boundary error: the
    # upstream may have produced a response, but Envoy commits no P3/P4
    # response to the client and the unclaimed bounded entry expires.
    "envoy_response_metadata_omitted": ("P1", "P2"),
    "p2_to_p3_timeout": ("P1", "P2"),
}
CONNECTORS = {"envoy", "traefik"}
MANIFEST_KEYS = {"schema", "connector", "case", "case_artifact", "expected_phases", "client_observation", "upstream_observation", "cleanup"}
ARTIFACT_KEYS = {"id", "event_log"}
UPSTREAM_KEYS = {"lease_observed", "request_terminal", "response_observed"}
CLIENT_KEYS = {
    "lease_observed", "visible_status", "redirect_location_verified",
    "p4_outcome", "p4_visible_status", "p4_response_committed",
}
CLEANUP_KEYS = {"count", "status"}
RAW_EVENT_KEYS = {
    "decision_id", "connector", "phase", "outcome", "reason", "requested_action",
    "actual_host_action", "visible_status", "cleanup_outcome", "event_time", "rule_id",
    "request_path", "response_path", "transport",
}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
DECISION_ID = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
RULE_ID = re.compile(r"^\d{1,128}$", re.ASCII)
FORBIDDEN_KEY_WORDS = ("body", "lease", "credential", "secret", "token", "password")
PIPELINE_METADATA = {
    "envoy": ("envoy.ext_authz", "envoy.ext_proc", "envoy_ext_authz_ext_proc_grpc"),
    "traefik": ("traefik.forwardAuth", "traefik.native_uds", "traefik_forwardauth_private_uds"),
}
CASE_RULE_IDS = {
    "p1_deny": ("P1", "1101001"),
    "p2_deny": ("P2", "1102001"),
    "p3_deny": ("P3", "1103001"),
    "p3_redirect": ("P3", "1103002"),
    "p4_safe": ("P4", "1104002"),
}
MANIFEST_CASE_ARTIFACT = "manifest.case_artifact"
MANIFEST_CLEANUP = "manifest.cleanup"


class EvidenceError(ValueError):
    """A malformed or insufficient evidence receipt."""


@dataclass(frozen=True)
class Verification:
    status: str
    connector: str | None
    case: str | None
    artifact_id: str | None
    decision_id: str | None
    phases: tuple[str, ...]
    errors: tuple[str, ...]

    # A receipt is deliberately not a rule-vector or real-host acceptance.
    # Case artifacts are supplied by the trusted operator case driver, so the
    # verifier can establish only metadata/lifecycle consistency.
    scope: str = EVIDENCE_SCOPE
    catalog_acceptance: bool = False

    @property
    def lifecycle_verified(self) -> bool:
        return self.status == "LIFECYCLE_ONLY"

    @property
    def passed(self) -> bool:
        """Compatibility alias for a valid lifecycle-only receipt.

        Callers must inspect ``status``/``catalog_acceptance`` before treating
        this as any broader validation result.
        """
        return self.lifecycle_verified

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "connector": self.connector, "case": self.case,
                "artifact_id": self.artifact_id, "decision_id": self.decision_id,
                "phases": list(self.phases), "scope": self.scope,
                "lifecycle_verified": self.lifecycle_verified,
                "catalog_acceptance": self.catalog_acceptance,
                "errors": list(self.errors)}


@dataclass(frozen=True)
class _ManifestContext:
    connector: str
    case: str
    expected: tuple[str, ...]
    artifact_id: str
    event_log: str
    client_status: Any
    redirect_location_verified: bool
    request_terminal: bool
    response_observed: bool
    p4_outcome: str
    p4_visible_status: Any
    p4_committed: bool


def _manifest_identity(
    manifest: dict[str, Any], manifest_path: Path, expected_event_log: Path | None
) -> tuple[str, str, tuple[str, ...], str, str]:
    if _string(manifest["schema"], "manifest.schema") != SCHEMA:
        raise EvidenceError(f"manifest.schema must be {SCHEMA}")
    connector = _string(manifest["connector"], "manifest.connector")
    if connector not in CONNECTORS:
        raise EvidenceError("manifest.connector must be envoy or traefik")
    case = _string(manifest["case"], "manifest.case")
    if case not in CASES:
        raise EvidenceError(f"manifest.case must be one of: {', '.join(sorted(CASES))}")
    expected = manifest["expected_phases"]
    if not isinstance(expected, list) or tuple(expected) != CASES[case]:
        raise EvidenceError("manifest.expected_phases must exactly match the selected case")
    artifact = _expect_object(manifest["case_artifact"], MANIFEST_CASE_ARTIFACT)
    _reject_unknown(artifact, ARTIFACT_KEYS, MANIFEST_CASE_ARTIFACT)
    _required(artifact, ARTIFACT_KEYS, MANIFEST_CASE_ARTIFACT)
    artifact_id = _string(artifact["id"], f"{MANIFEST_CASE_ARTIFACT}.id", SAFE_ID)
    event_log = _safe_leaf_name(
        _string(artifact["event_log"], f"{MANIFEST_CASE_ARTIFACT}.event_log"),
        "case_artifact.event_log",
    )
    if expected_event_log is not None:
        if not expected_event_log.is_absolute() or expected_event_log.parent != manifest_path.parent:
            raise EvidenceError("--expected-event-log must be an absolute regular non-symlink file")
        if expected_event_log.name != event_log:
            raise EvidenceError("manifest event log does not match --expected-event-log")
    return connector, case, tuple(expected), artifact_id, event_log


def _manifest_observations(
    manifest: dict[str, Any], runtime_root: PrivateRuntimeRoot
) -> tuple[Any, bool, bool, bool, str, Any, bool]:
    client_path = _safe_observation_name(
        _string(manifest["client_observation"], "manifest.client_observation"),
        "manifest.client_observation",
    )
    upstream_path = _safe_observation_name(
        _string(manifest["upstream_observation"], "manifest.upstream_observation"),
        "manifest.upstream_observation",
    )
    client = _load_observation(runtime_root, client_path, CLIENT_KEYS, CLIENT_KEYS, "client_observation")
    upstream = _load_observation(runtime_root, upstream_path, UPSTREAM_KEYS, UPSTREAM_KEYS, "upstream_observation")
    if _bool(upstream["lease_observed"], "upstream_observation.lease_observed"):
        raise EvidenceError("upstream reports a lease observed")
    request_terminal = _bool(upstream["request_terminal"], "upstream_observation.request_terminal")
    response_observed = _bool(upstream["response_observed"], "upstream_observation.response_observed")
    if _bool(client["lease_observed"], "client_observation.lease_observed"):
        raise EvidenceError("client reports a lease observed")
    client_status = client["visible_status"]
    if client_status is not None:
        _status(client_status, "client_observation.visible_status")
    redirect_location_verified = _bool(
        client["redirect_location_verified"],
        "client_observation.redirect_location_verified",
    )
    p4_outcome = _string(client["p4_outcome"], "client_observation.p4_outcome")
    if p4_outcome not in {"none", "abort", "reset"}:
        raise EvidenceError("client_observation.p4_outcome is invalid")
    p4_status = client["p4_visible_status"]
    if p4_status is not None:
        _status(p4_status, "client_observation.p4_visible_status")
    p4_committed = _bool(client["p4_response_committed"], "client_observation.p4_response_committed")
    return (
        client_status,
        redirect_location_verified,
        request_terminal,
        response_observed,
        p4_outcome,
        p4_status,
        p4_committed,
    )


def _validate_manifest_cleanup(manifest: dict[str, Any]) -> None:
    cleanup = _expect_object(manifest["cleanup"], MANIFEST_CLEANUP)
    _reject_unknown(cleanup, CLEANUP_KEYS, MANIFEST_CLEANUP)
    _required(cleanup, CLEANUP_KEYS, MANIFEST_CLEANUP)
    if type(cleanup["count"]) is not int or cleanup["count"] != 1:
        raise EvidenceError("manifest.cleanup.count must be exactly one")
    if cleanup["status"] != "completed":
        raise EvidenceError("manifest.cleanup.status must be completed")


def _manifest_context(
    manifest_path: Path, runtime_root: PrivateRuntimeRoot, expected_event_log: Path | None
) -> _ManifestContext:
    manifest = _expect_object(_json_value(runtime_root, manifest_path.name, "manifest", MAX_EVENT_LOG_BYTES), "manifest")
    _reject_unknown(manifest, MANIFEST_KEYS, "manifest")
    _required(manifest, MANIFEST_KEYS, "manifest")
    connector, case, expected, artifact_id, event_log = _manifest_identity(
        manifest, manifest_path, expected_event_log
    )
    client_status, redirect_location_verified, request_terminal, response_observed, p4_outcome, p4_visible_status, p4_committed = _manifest_observations(
        manifest, runtime_root
    )
    _validate_manifest_cleanup(manifest)
    return _ManifestContext(
        connector, case, tuple(expected), artifact_id, event_log, client_status,
        redirect_location_verified,
        request_terminal, response_observed, p4_outcome, p4_visible_status, p4_committed,
    )


def _expect_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must be an object")
    return value


def _reject_unknown(value: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        for key in unknown:
            if any(word in key.lower() for word in FORBIDDEN_KEY_WORDS):
                raise EvidenceError(f"{path}.{key} is a forbidden payload field")
        raise EvidenceError(f"{path} contains unknown field(s): {', '.join(unknown)}")


def _required(value: dict[str, Any], keys: Iterable[str], path: str) -> None:
    missing = [key for key in keys if key not in value]
    if missing:
        raise EvidenceError(f"{path} is missing required field(s): {', '.join(missing)}")


def _string(value: Any, path: str, pattern: re.Pattern[str] | None = None, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise EvidenceError(f"{path} must be a string")
    if "\r" in value or "\n" in value or len(value) > 256:
        raise EvidenceError(f"{path} exceeds metadata bounds")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EvidenceError(f"{path} has an invalid format")
    return value


def _bool(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise EvidenceError(f"{path} must be boolean")
    return value


def _status(value: Any, path: str) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise EvidenceError(f"{path} must be an HTTP status integer")
    return value


def _json_value(root: PrivateRuntimeRoot, name: str, label: str, maximum_bytes: int) -> Any:
    try:
        text = root.read_text(name, label=label, maximum_bytes=maximum_bytes)
        return json.loads(text, object_pairs_hook=_no_duplicate_pairs)
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        if isinstance(exc, OSError) and getattr(exc, "errno", None) == 40:
            raise EvidenceError(f"{label} must be a regular non-symlink file") from exc
        raise EvidenceError(f"cannot read JSON {name}: {exc}") from exc


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _safe_leaf_name(name: str, field: str) -> str:
    relative = Path(name)
    if relative.is_absolute() or relative.name != name or name in {"", ".", ".."}:
        raise EvidenceError(f"{field} must be a relative basename")
    return name


def _safe_observation_name(name: str, field: str) -> str:
    return _safe_leaf_name(name, field)


def _load_observation(root: PrivateRuntimeRoot, name: str, allowed: set[str], required: set[str], label: str) -> dict[str, Any]:
    value = _expect_object(_json_value(root, name, label, MAX_OBSERVATION_BYTES), label)
    _reject_unknown(value, allowed, label)
    _required(value, required, label)
    return value


def _load_raw_events(root: PrivateRuntimeRoot, name: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    try:
        text = root.read_text(name, label="event log", maximum_bytes=MAX_EVENT_LOG_BYTES)
        for number, raw_line in enumerate(text.splitlines(keepends=True), 1):
            if len(raw_line.encode("utf-8")) > MAX_EVENT_LINE_BYTES:
                raise EvidenceError(f"event log line {number} exceeds metadata bounds")
            if not raw_line.strip():
                raise EvidenceError(f"event log line {number} is blank")
            try:
                event = json.loads(raw_line, object_pairs_hook=_no_duplicate_pairs)
            except EvidenceError:
                raise
            except json.JSONDecodeError as exc:
                raise EvidenceError(f"event log line {number} is not JSON: {exc}") from exc
            events.append(_expect_object(event, f"event[{number}]"))
    except EvidenceError:
        raise
    except (OSError, UnicodeError) as exc:
        if isinstance(exc, OSError) and getattr(exc, "errno", None) == 40:
            raise EvidenceError("event log must be a regular non-symlink file") from exc
        raise EvidenceError(f"cannot read event log {name}: {exc}") from exc
    if not events:
        raise EvidenceError("event log must contain at least one event")
    return events


def _validate_event(event: dict[str, Any], number: int, connector: str) -> tuple[str, str]:
    path = f"event[{number}]"
    _reject_unknown(event, RAW_EVENT_KEYS, path)
    _required(event, {"decision_id", "connector", "phase", "outcome", "event_time", "request_path", "response_path", "transport"}, path)
    decision_id = _string(event["decision_id"], f"{path}.decision_id", DECISION_ID)
    if _string(event["connector"], f"{path}.connector") != connector:
        raise EvidenceError(f"{path}.connector does not match manifest connector")
    request_path = _string(event["request_path"], f"{path}.request_path")
    response_path = _string(event["response_path"], f"{path}.response_path")
    transport = _string(event["transport"], f"{path}.transport")
    if (request_path, response_path, transport) != PIPELINE_METADATA[connector]:
        raise EvidenceError(f"{path} pipeline metadata does not match the connector")
    phase = _string(event["phase"], f"{path}.phase")
    if phase not in PHASES and phase not in LIFECYCLE_PHASES:
        raise EvidenceError(f"{path}.phase is not a recognized observer phase")
    _string(event["outcome"], f"{path}.outcome")
    event_time = _string(event["event_time"], f"{path}.event_time")
    try:
        _datetime.datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{path}.event_time is not RFC3339 metadata") from exc
    for key in ("reason", "requested_action", "actual_host_action", "cleanup_outcome"):
        if key in event:
            _string(event[key], f"{path}.{key}", allow_empty=True)
    if "visible_status" in event:
        _status(event["visible_status"], f"{path}.visible_status")
    if "rule_id" in event:
        _string(event["rule_id"], f"{path}.rule_id", RULE_ID)
    return phase, decision_id


def _sequence_metadata(
    events: list[dict[str, Any]], connector: str
) -> tuple[set[str], dict[str, int], list[str], int]:
    ids: set[str] = set()
    phase_positions: dict[str, int] = {}
    terminal_cleanup: list[str] = []
    terminal_position = 0
    for number, event in enumerate(events, 1):
        phase, decision_id = _validate_event(event, number, connector)
        ids.add(decision_id)
        if phase in PHASES:
            if phase in phase_positions:
                raise EvidenceError(f"raw event phase {phase} occurs more than once")
            phase_positions[phase] = number
        if phase == "terminal":
            terminal_position = number
            terminal_cleanup.append(event.get("cleanup_outcome", ""))
    return ids, phase_positions, terminal_cleanup, terminal_position


def _validate_event_sequence(
    events: list[dict[str, Any]], connector: str, expected: list[str], case: str
) -> tuple[str, list[dict[str, Any]]]:
    ids, phase_positions, terminal_cleanup, terminal_position = _sequence_metadata(events, connector)
    if len(ids) != 1:
        raise EvidenceError("raw case log must contain exactly one decision_id")
    if tuple(sorted(phase_positions, key=phase_positions.get)) != tuple(expected):
        raise EvidenceError("raw P1..P4 observer events are missing or out of order")
    if len(terminal_cleanup) != 1 or terminal_cleanup != ["closed"]:
        raise EvidenceError("raw case log must contain exactly one terminal cleanup with cleanup_outcome closed")
    if terminal_position != len(events):
        raise EvidenceError("raw terminal cleanup must be the final observer event")
    if case in CASE_RULE_IDS:
        phase, rule_id = CASE_RULE_IDS[case]
        event = next(event for event in events if event.get("phase") == phase)
        if event.get("rule_id") != rule_id:
            raise EvidenceError(f"{case} requires raw {phase} rule_id={rule_id}")
    return next(iter(ids)), [
        event for event in events if event.get("phase") in {"host_action", "request_host_action"}
    ]


def validate_raw_event_records(
    events: list[dict[str, Any]], connector: str, case: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Validate one connector case before an adapter persists its raw event log."""

    if connector not in CONNECTORS:
        raise EvidenceError("raw event connector is not supported")
    if case not in CASES:
        raise EvidenceError("raw event case is not supported")
    return _validate_event_sequence(events, connector, list(CASES[case]), case)


def _phase_action(events: list[dict[str, Any]], case: str, phase: str, action: str) -> None:
    event = next(event for event in events if event.get("phase") == phase)
    if event.get("requested_action") != action:
        raise EvidenceError(f"{case} requires raw {phase} requested_action={action}")


def _matching_action(
    action_events: list[dict[str, Any]], action: str, status_class: tuple[int, int] | None = None
) -> dict[str, Any] | None:
    for event in action_events:
        if event.get("actual_host_action") != action:
            continue
        status = event.get("visible_status")
        if status_class is not None and (
            not isinstance(status, int) or not status_class[0] <= status <= status_class[1]
        ):
            continue
        return event
    return None


def _verify_oversize(
    events: list[dict[str, Any]], action_events: list[dict[str, Any]], client_status: Any,
    request_terminal: bool, response_observed: bool,
) -> None:
    p2 = next((event for event in events if event.get("phase") == "P2"), None)
    native_status = p2.get("visible_status") if p2 is not None else None
    oversize = None
    if native_status in (403, 413):
        oversize = _matching_action(action_events, "deny", (native_status, native_status))
    if (
        oversize is None
        or p2 is None
        or client_status != native_status
    ):
        raise EvidenceError("P2 oversize requires matching native 403/413 P2, request-side deny and client statuses")
    if not request_terminal or response_observed:
        raise EvidenceError("P2 oversize requires request termination before upstream observation")


def _verify_allow(
    events: list[dict[str, Any]], case: str, client_status: Any, request_terminal: bool, response_observed: bool
) -> None:
    for phase in ("P1", "P2"):
        _phase_action(events, case, phase, "allow")
    if client_status is None or not 200 <= client_status <= 299:
        raise EvidenceError(f"{case} requires a 2xx client-visible status")
    if request_terminal or not response_observed:
        raise EvidenceError(f"{case} requires upstream response observation without request termination")
    if any(event.get("phase") == "request_host_action" for event in events):
        raise EvidenceError(f"{case} rejects request_host_action evidence")


def _verify_timeout(
    events: list[dict[str, Any]], connector: str, client_status: Any, request_terminal: bool, response_observed: bool,
    p4_committed: bool, p4_outcome: str, p4_visible_status: Any,
) -> None:
    for phase in ("P1", "P2"):
        _phase_action(events, "p2_to_p3_timeout", phase, "allow")
    if client_status != 503:
        raise EvidenceError("P2-to-P3 timeout requires a real 503 client status")
    if request_terminal or not response_observed:
        raise EvidenceError("P2-to-P3 timeout requires upstream request observation without request termination")
    if p4_committed or p4_outcome != "none" or p4_visible_status is not None:
        raise EvidenceError("P2-to-P3 timeout must stop before P4 response commitment")
    expected_events = ("P1", "P2", "lease", "terminal")
    if connector == "traefik":
        expected_events = ("reservation",) + expected_events
    if tuple(event.get("phase") for event in events) != expected_events:
        raise EvidenceError("P2-to-P3 timeout requires one unclaimed lease followed directly by timeout cleanup")
    if connector == "traefik" and events[0].get("outcome") != "reserved":
        raise EvidenceError("P2-to-P3 timeout requires one pre-admission reservation before P1")
    lease = events[-2]
    terminal = events[-1]
    if lease.get("outcome") != "issued" or terminal.get("reason") != "timeout":
        raise EvidenceError("P2-to-P3 timeout requires issued lease followed by timeout cleanup")


def _verify_denial(
    events: list[dict[str, Any]], action_events: list[dict[str, Any]], case: str,
    client_status: Any, request_terminal: bool, response_observed: bool,
) -> None:
    if client_status is None or not 400 <= client_status <= 599 or _matching_action(
        action_events, "deny", (client_status, client_status)
    ) is None:
        raise EvidenceError(f"{case} requires matching raw deny action and client-visible status")
    if case in {"p1_deny", "p2_deny"} and (not request_terminal or response_observed):
        raise EvidenceError(f"{case} requires request termination before upstream observation")
    if case == "p1_deny":
        _phase_action(events, case, "P1", "deny")
    if case == "p2_deny":
        _phase_action(events, case, "P1", "allow")
        _phase_action(events, case, "P2", "deny")
    if case == "p3_deny":
        _phase_action(events, case, "P3", "deny")
        if request_terminal or not response_observed:
            raise EvidenceError("p3_deny requires upstream response observation without request termination")


def _verify_redirect(
    events: list[dict[str, Any]], action_events: list[dict[str, Any]], client_status: Any,
    redirect_location_verified: bool, request_terminal: bool, response_observed: bool,
) -> None:
    if client_status != 302 or _matching_action(
        action_events, "redirect", (302, 302)
    ) is None:
        raise EvidenceError("P3 redirect requires matching raw redirect action and canonical HTTP 302 status")
    if not redirect_location_verified:
        raise EvidenceError("P3 redirect requires an exact client-boundary Location attestation")
    _phase_action(events, "p3_redirect", "P3", "redirect")
    if request_terminal or not response_observed:
        raise EvidenceError("p3_redirect requires upstream response observation without request termination")


def _verify_p4_safe(
    events: list[dict[str, Any]], action_events: list[dict[str, Any]], p4_outcome: str,
    client_status: Any, p4_visible_status: Any, request_terminal: bool,
    response_observed: bool, p4_committed: bool,
) -> None:
    p4_events = [event for event in events if event.get("phase") == "P4"]
    log_only = _matching_action(action_events, "log_only")
    if not p4_events or log_only is None:
        raise EvidenceError("P4 Safe requires raw P4 and host_action=log_only evidence")
    _phase_action(events, "p4_safe", "P4", "deny")
    if p4_outcome != "none":
        raise EvidenceError("P4 Safe cannot claim a client abort/reset")
    if request_terminal or not response_observed or not p4_committed:
        raise EvidenceError("P4 Safe requires a committed upstream response without request termination")
    if (
        type(client_status) is not int
        or client_status != log_only.get("visible_status")
        or p4_visible_status != client_status
    ):
        raise EvidenceError("P4 Safe requires matching committed client and log-only visible statuses")


def _verify_metadata_omitted(
    events: list[dict[str, Any]], client_status: Any, request_terminal: bool,
    response_observed: bool, p4_committed: bool,
) -> None:
    if client_status != 503:
        raise EvidenceError("missing lease metadata requires a fail-closed 503 client status")
    if request_terminal or response_observed or p4_committed:
        raise EvidenceError("missing lease metadata must stop before upstream response observation")
    reservations = [event for event in events if event.get("phase") == "reservation"]
    lease = next((event for event in events if event.get("phase") == "lease"), None)
    terminal = next((event for event in events if event.get("phase") == "terminal"), None)
    if len(reservations) != 1 or lease is not None or terminal is None or terminal.get("reason") not in {"abort", "disconnect"}:
        raise EvidenceError(
            "missing lease metadata requires one pre-admission reservation and abort/disconnect cleanup without a lease event"
        )


def _verify_envoy_response_metadata_omitted(
    events: list[dict[str, Any]], client_status: Any, request_terminal: bool,
    response_observed: bool, p4_outcome: str, p4_visible_status: Any,
    p4_committed: bool,
) -> None:
    """Verify Envoy's response-boundary missing-metadata failure semantics."""
    for phase in ("P1", "P2"):
        _phase_action(events, "envoy_response_metadata_omitted", phase, "allow")
    if client_status != 503:
        raise EvidenceError("Envoy response metadata omission requires a fail-closed 503 client status")
    if request_terminal or not response_observed:
        raise EvidenceError("Envoy response metadata omission requires an observed upstream response without request termination")
    if p4_committed or p4_outcome != "none" or p4_visible_status is not None:
        raise EvidenceError("Envoy response metadata omission must stop before P4 response commitment")
    phases = tuple(event.get("phase") for event in events)
    if phases != ("P1", "P2", "lease", "terminal"):
        raise EvidenceError("Envoy response metadata omission requires P1/P2, one unclaimed lease, and terminal cleanup only")
    if events[2].get("outcome") != "issued":
        raise EvidenceError("Envoy response metadata omission requires one issued lease")
    if events[-1].get("reason") != "timeout":
        raise EvidenceError("Envoy response metadata omission requires bounded timeout cleanup")


def _verify(manifest_path: Path, runtime_root: PrivateRuntimeRoot, expected_event_log: Path | None = None) -> Verification:
    context = _manifest_context(manifest_path, runtime_root, expected_event_log)
    events = _load_raw_events(runtime_root, context.event_log)
    decision_id, action_events = validate_raw_event_records(
        events, context.connector, context.case
    )

    if context.case == "p2_oversize":
        _verify_oversize(
            events,
            action_events,
            context.client_status,
            context.request_terminal,
            context.response_observed,
        )
        _phase_action(events, context.case, "P1", "allow")
        _phase_action(events, context.case, "P2", "deny")
    elif context.case in {"p1_allow", "p2_allow"}:
        _verify_allow(events, context.case, context.client_status, context.request_terminal, context.response_observed)
    elif context.case == "p2_to_p3_timeout":
        _verify_timeout(
            events,
            context.connector,
            context.client_status,
            context.request_terminal,
            context.response_observed,
            context.p4_committed,
            context.p4_outcome,
            context.p4_visible_status,
        )
    elif context.case in {"p1_deny", "p2_deny", "p3_deny"}:
        _verify_denial(events, action_events, context.case, context.client_status, context.request_terminal, context.response_observed)
    elif context.case == "p3_redirect":
        _verify_redirect(
            events,
            action_events,
            context.client_status,
            context.redirect_location_verified,
            context.request_terminal,
            context.response_observed,
        )
    elif context.case == "p4_safe":
        _verify_p4_safe(
            events,
            action_events,
            context.p4_outcome,
            context.client_status,
            context.p4_visible_status,
            context.request_terminal,
            context.response_observed,
            context.p4_committed,
        )
    elif context.case == "metadata_omitted":
        _verify_metadata_omitted(events, context.client_status, context.request_terminal, context.response_observed, context.p4_committed)
    elif context.case == "envoy_response_metadata_omitted":
        if context.connector != "envoy":
            raise EvidenceError("Envoy response metadata omission is valid only for the Envoy composite")
        _verify_envoy_response_metadata_omitted(
            events,
            context.client_status,
            context.request_terminal,
            context.response_observed,
            context.p4_outcome,
            context.p4_visible_status,
            context.p4_committed,
        )
    if context.case == "p4_strict":
        # A driver-side observation is not proof that Envoy/Traefik invoked a
        # real client-visible reset/abort primitive. No current runner has that
        # primitive, so this case intentionally cannot become a passing result.
        return Verification("NON_PASS", context.connector, context.case, context.artifact_id, decision_id, context.expected,
                            ("P4 Strict remains non-promoting without independently demonstrated host reset/abort",))
    return Verification("LIFECYCLE_ONLY", context.connector, context.case, context.artifact_id, decision_id, context.expected, ())


def verify_manifest(path: str | Path, expected_event_log: str | Path | None = None, runtime_root: str | Path | None = None) -> Verification:
    manifest_path = Path(path)
    if not manifest_path.is_absolute():
        manifest_path = manifest_path.absolute()
    root_path = Path(runtime_root).absolute() if runtime_root is not None else manifest_path.parent
    if manifest_path.parent != root_path:
        raise EvidenceError("manifest must be a direct child of --runtime-root")
    try:
        with open_private_runtime_root(root_path) as private_root:
            expected_path = Path(expected_event_log).absolute() if expected_event_log is not None else None
            return _verify(manifest_path, private_root, expected_path)
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="isolated composite evidence manifest JSON")
    parser.add_argument("--expected-event-log", type=Path, help="absolute event-log path that must exactly match the manifest reference")
    parser.add_argument("--runtime-root", type=Path, required=True, help="existing exact private 0700 runtime root containing the manifest and direct 0600 leaves")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit a JSON result")
    args = parser.parse_args(argv)
    try:
        result = verify_manifest(args.manifest, args.expected_event_log, args.runtime_root)
    except EvidenceError as exc:
        result = Verification("INVALID", None, None, None, None, (), (str(exc),))
    if args.json_output:
        print(json.dumps(result.as_dict(), sort_keys=True))
    else:
        print(f"{result.status}: {result.errors[0] if result.errors else 'composite evidence verified'}")
    return 0 if result.lifecycle_verified else 1


if __name__ == "__main__":
    sys.exit(main())
