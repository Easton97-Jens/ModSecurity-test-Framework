#!/usr/bin/env python3
"""Validate the evidence properties that gate full-lifecycle promotion.

This checker is deliberately conservative: an absent capability is not a
failure, but a connector that marks a capability ``verified`` must provide a
fresh strict-profile run that proves the corresponding property.  It therefore
cannot turn a compilation, a source audit, or a synthetic upstream probe into
a capability promotion.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
EVENTS_FILENAME = "events.jsonl"
TRANSPORT_LIFECYCLE_ARTIFACTS = {
    "client_log": "logs/client.log",
    "upstream_log": "logs/upstream.log",
    "transport_log": "logs/transport.log",
    "cleanup_log": "logs/cleanup.log",
    "transport_observations": "inventory/transport-observations.json",
    "connection_lifecycle": "inventory/connection-lifecycle.json",
    "barrier_events": "inventory/barrier-events.jsonl",
    "effective_config": "effective-config/manifest.json",
}
LIFECYCLE_COUNTERS = (
    "transactions_started",
    "transactions_finished",
    "transactions_destroyed",
    "request_body_finishes",
    "response_body_finishes",
    "intentional_aborts",
    "client_disconnects",
    "upstream_disconnects",
    "stream_resets",
    "timeouts",
    "short_writes",
    "write_would_block",
    "cleanup_normal",
    "cleanup_cancel",
    "cleanup_abort",
    "unexpected_engine_errors",
)
FORBIDDEN_TRANSPORT_KEYS = {
    "authorization",
    "body",
    "body_content",
    "body_payload",
    "body_snippet",
    "cookie",
    "matched_value",
    "password",
    "payload",
    "request_body",
    "response_body",
    "rule_message",
    "secret",
}

# A result is not full-lifecycle evidence merely because it is stored under a
# full-lifecycle-looking directory.  The selected native host path has to be
# carried by the canonical result itself, so compatibility evidence cannot be
# rendered or checked as native evidence by mistake.
FULL_LIFECYCLE_IDENTITIES = {
    "apache": {
        "host_profile": "native-httpd-module",
        "integration_mode": "native-httpd-module",
        "target": "full-lifecycle-apache",
    },
    "nginx": {
        "host_profile": "native-nginx-http-module",
        "integration_mode": "native-nginx-http-module",
        "target": "full-lifecycle-nginx",
    },
    "haproxy": {
        "host_profile": "native-htx-filter",
        "integration_mode": "native-htx-filter",
        "target": "full-lifecycle-haproxy-htx",
    },
    "envoy": {
        "host_profile": "ext_proc",
        "integration_mode": "ext_proc",
        "target": "full-lifecycle-envoy-ext-proc",
    },
    "traefik": {
        "host_profile": "native-middleware",
        "integration_mode": "native-traefik-middleware",
        "target": "full-lifecycle-traefik-native",
    },
    "lighttpd": {
        "host_profile": "patched-native",
        "integration_mode": "patched-native-lighttpd",
        "target": "full-lifecycle-lighttpd-patched",
    },
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON object required")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: JSON object required")
        records.append(value)
    return records


def capability_state(manifest: dict[str, Any], name: str) -> str:
    entry = manifest.get("capabilities", {}).get(name, {})
    return str(entry.get("state") or "") if isinstance(entry, dict) else ""


def profile_errors(result: dict[str, Any], connector: str) -> list[str]:
    """Reject generic or compatibility evidence before any promotion check."""

    expected = FULL_LIFECYCLE_IDENTITIES[connector]
    errors: list[str] = []
    if result.get("artifact_profile") != "full_lifecycle":
        errors.append("canonical full-lifecycle evidence requires artifact_profile=full_lifecycle")
    if result.get("host_profile") != expected["host_profile"]:
        errors.append(
            "canonical full-lifecycle evidence requires host_profile="
            f"{expected['host_profile']!r}"
        )
    if result.get("integration_mode") != expected["integration_mode"]:
        errors.append(
            "canonical full-lifecycle evidence requires integration_mode="
            f"{expected['integration_mode']!r}"
        )
    targets = result.get("executed_targets")
    if targets != [expected["target"]]:
        errors.append(
            "canonical full-lifecycle evidence requires executed_targets="
            f"[{expected['target']!r}]"
        )
    return errors


def expected_event_identity(
    result: dict[str, Any], connector: str | None, run_id: str | None,
) -> tuple[str, str, str] | None:
    """Return the selected native P4 identity or reject incomplete evidence.

    The run directory and command select the connector/run; the canonical
    result confirms the expected native integration mode.  A raw P4 event is
    evidence only when it carries every part of that same identity.  This is
    deliberately fail-closed: a rule ID and phase are not a producer or run
    identity, and absent identity metadata cannot be promoted.
    """
    selected_connector = connector if connector is not None else result.get("connector")
    selected_run_id = run_id if run_id is not None else result.get("run_id")
    if (
        not isinstance(selected_connector, str)
        or selected_connector not in FULL_LIFECYCLE_IDENTITIES
        or not isinstance(selected_run_id, str)
        or not selected_run_id
    ):
        return None
    expected = FULL_LIFECYCLE_IDENTITIES[selected_connector]
    integration_mode = expected["integration_mode"]
    if (
        result.get("connector") != selected_connector
        or result.get("run_id") != selected_run_id
        or result.get("host_profile") != expected["host_profile"]
        or result.get("integration_mode") != integration_mode
    ):
        return None
    return selected_connector, selected_run_id, integration_mode


def record_transaction_ids(record: dict[str, Any]) -> set[str]:
    """Return canonical result-to-event transaction IDs, rejecting omissions."""
    values = record.get("transaction_ids")
    if not isinstance(values, list):
        return set()
    return {
        str(value)
        for value in values
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value)
    }


def matching_events(
    events: list[dict[str, Any]], rule_id: object, identity: tuple[str, str, str] | None,
    transaction_ids: set[str],
) -> list[dict[str, Any]]:
    """Select only same-run, same-host, same-transaction canonical P4 events."""
    if identity is None or not transaction_ids:
        return []
    connector, run_id, integration_mode = identity
    return [
        event
        for event in events
        if event.get("connector") == connector
        and event.get("run_id") == run_id
        and event.get("integration_mode") == integration_mode
        and str(event.get("transaction_id") or "") in transaction_ids
        and event.get("rule_id") == rule_id
        and event.get("phase") == 4
    ]


def nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def event_transaction_ids(events: list[dict[str, Any]], predicate: Any) -> set[str]:
    return {
        str(event.get("transaction_id"))
        for event in events
        if event.get("transaction_id") and predicate(event)
    }


def canonical_transport_value(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def lifecycle_counter_errors(counters: dict[str, Any], connector: str) -> list[str]:
    errors: list[str] = []
    if counters.get("connector") != connector:
        errors.append("lifecycle counters connector does not match run")
    for name in LIFECYCLE_COUNTERS:
        if not nonnegative_integer(counters.get(name)):
            errors.append(f"lifecycle counter {name} must be a nonnegative integer")
    bound = counters.get("transport_counters_bound")
    if bound is not None and not isinstance(bound, bool):
        errors.append("transport_counters_bound must be Boolean when present")
    return errors


def lifecycle_balance_errors(counters: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    started = counters["transactions_started"]
    finished = counters["transactions_finished"]
    destroyed = counters["transactions_destroyed"]
    if not (started >= finished >= destroyed):
        errors.append("lifecycle counters violate started >= finished >= destroyed")
    if started != finished or finished != destroyed:
        errors.append("completed selected host run leaves transaction lifecycle counts unbalanced")
    return errors


def record_counter(records: list[dict[str, Any]], name: str) -> int:
    return sum(
        value
        for record in records
        if isinstance((value := record.get(name, 0)), int)
        and not isinstance(value, bool)
        and value >= 0
    )


def expected_bound_lifecycle_counters(records: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "client_disconnects": record_counter(records, "client_disconnect"),
        "upstream_disconnects": record_counter(records, "upstream_disconnect"),
        "stream_resets": record_counter(records, "stream_reset"),
        "timeouts": record_counter(records, "timeout"),
        "short_writes": record_counter(records, "short_writes"),
        "write_would_block": record_counter(records, "write_would_block"),
        "cleanup_normal": sum(record.get("cleanup_reason") == "normal" for record in records),
        "cleanup_cancel": sum(record.get("cleanup_reason") in {"cancelled", "client_disconnected", "upstream_disconnected"} for record in records),
        "cleanup_abort": sum(record.get("cleanup_reason") in {"strict_abort", "stream_reset"} for record in records),
    }


def bound_lifecycle_errors(
    counters: dict[str, Any], records: list[dict[str, Any]], events: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for name, expected_value in expected_bound_lifecycle_counters(records).items():
        if counters[name] != expected_value:
            errors.append(f"lifecycle counter {name} does not match bound connection lifecycle")
    if counters["intentional_aborts"] < record_counter(records, "intentional_abort"):
        errors.append("intentional_aborts is below bound strict lifecycle accounting")
    observed_aborts = event_transaction_ids(
        events,
        lambda event: event.get("intentional_abort") is True
        or canonical_transport_value(event.get("actual_action")) in {"abort_connection", "stream_reset"},
    )
    if counters["intentional_aborts"] > len(observed_aborts):
        errors.append("intentional_aborts has no matching strict action event")
    return errors


def lifecycle_errors(
    run_dir: Path, connector: str, result: dict[str, Any] | None = None,
) -> list[str]:
    # A blocked-before-execution host stage is a valid canonical outcome.  The
    # runner intentionally does not manufacture engine accounting for it, so
    # this inventory check must not turn an honest BLOCKED/NOT EXECUTED result
    # into a false failure merely because lifecycle-counters.json is absent.
    if result is not None and (
        result.get("exit_code") != 0 or result.get("started") is not True
    ):
        return []
    path = run_dir / "lifecycle-counters.json"
    if not path.is_file():
        return ["missing lifecycle-counters.json"]
    try:
        counters = load_json(path)
        events = load_jsonl(run_dir / EVENTS_FILENAME)
    except (OSError, ValueError) as exc:
        return [f"cannot read lifecycle inventory: {exc}"]
    errors = lifecycle_counter_errors(counters, connector)
    if errors:
        return errors
    errors.extend(lifecycle_balance_errors(counters))
    bound = counters.get("transport_counters_bound")
    # JSON numbers compare equal to booleans in Python (`1 == True`).  The
    # sidecar contract deliberately requires a JSON Boolean, so use an
    # identity/type check rather than membership equality here.
    if bound is not True:
        # Generic host events may expose a local cancellation or write error
        # without the full case/transaction/lifecycle correlation needed for a
        # transport record.  They are diagnostic only; the Framework will
        # require bound records before accepting a transport PASS.
        return errors
    try:
        lifecycle = load_json(run_dir / "inventory/connection-lifecycle.json")
    except (OSError, ValueError) as exc:
        return [*errors, f"cannot read bound connection lifecycle inventory: {exc}"]
    records = lifecycle.get("records")
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        return [*errors, "bound connection lifecycle records must be an object list"]

    return [*errors, *bound_lifecycle_errors(counters, records, events)]


def contains_forbidden_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(key.lower() in FORBIDDEN_TRANSPORT_KEYS or contains_forbidden_key(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(contains_forbidden_key(item) for item in value)
    return False


def missing_transport_artifact_errors(run_dir: Path) -> list[str]:
    errors: list[str] = []
    for name, relative in TRANSPORT_LIFECYCLE_ARTIFACTS.items():
        path = run_dir / relative
        if not path.is_file() or path.is_symlink():
            errors.append(f"missing payload-free transport artifact {name}")
    return errors


def load_transport_artifacts(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    observations = load_json(run_dir / TRANSPORT_LIFECYCLE_ARTIFACTS["transport_observations"])
    connections = load_json(run_dir / TRANSPORT_LIFECYCLE_ARTIFACTS["connection_lifecycle"])
    effective_config = load_json(run_dir / TRANSPORT_LIFECYCLE_ARTIFACTS["effective_config"])
    barriers = load_jsonl(run_dir / TRANSPORT_LIFECYCLE_ARTIFACTS["barrier_events"])
    return observations, connections, effective_config, barriers


def transport_document_errors(
    connector: str, observations: dict[str, Any], connections: dict[str, Any], barriers: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for label, document in (("transport observations", observations), ("connection lifecycle", connections)):
        if document.get("connector") != connector:
            errors.append(f"{label} connector does not match run")
        if not isinstance(document.get("run_id"), str) or not document.get("run_id"):
            errors.append(f"{label} is missing its bounded run identity")
        if contains_forbidden_key(document):
            errors.append(f"{label} contains forbidden payload metadata")
    if contains_forbidden_key(barriers):
        errors.append("barrier events contain forbidden payload metadata")
    return errors


def transport_observation_errors(observations: dict[str, Any]) -> list[str]:
    records = observations.get("observations")
    if not isinstance(records, list):
        return ["transport observations observations must be a list"]
    required = {
        "protocol", "case_id", "transport_case_id", "transaction_id", "rule_id",
        "phase", "event", "message_id", "requested_action", "actual_action",
        "response_committed", "first_byte_received", "eos_received",
        "client_result", "transport_result", "host_survived", "followup_request_result",
    }
    for record in records:
        if not isinstance(record, dict) or not required.issubset(record):
            return ["transport observation is missing required causal fields"]
        if record.get("host_survived") is True and record.get("followup_request_result") != "completed":
            return ["host_survived=true requires an independent follow-up observation"]
    return []


def transport_connection_and_config_errors(
    connector: str, connections: dict[str, Any], effective_config: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if not isinstance(connections.get("records"), list):
        errors.append("connection lifecycle records must be a list")
    if effective_config.get("connector") != connector:
        errors.append("effective config connector does not match run")
    if not isinstance(effective_config.get("files"), list):
        errors.append("effective config files must be a list")
    if contains_forbidden_key(effective_config):
        errors.append("effective config contains forbidden payload metadata")
    return errors


def transport_artifact_errors(run_dir: Path, connector: str) -> list[str]:
    errors = missing_transport_artifact_errors(run_dir)
    if errors:
        return errors
    try:
        observations, connections, effective_config, barriers = load_transport_artifacts(run_dir)
    except (OSError, ValueError) as exc:
        return [f"cannot read transport artifacts: {exc}"]
    errors.extend(transport_document_errors(connector, observations, connections, barriers))
    errors.extend(transport_observation_errors(observations))
    errors.extend(transport_connection_and_config_errors(connector, connections, effective_config))
    return errors


def first_byte_errors(
    run_dir: Path,
    manifest: dict[str, Any],
    result: dict[str, Any],
    *,
    connector: str | None = None,
    run_id: str | None = None,
) -> list[str]:
    claimed = capability_state(manifest, "first_byte_before_response_end") == "verified"
    verified = set(result.get("capabilities_verified") or [])
    claimed = claimed or "first_byte_before_response_end" in verified
    if not claimed:
        return []
    if result.get("artifact_profile") != "full_lifecycle":
        return ["first-byte promotion requires a full_lifecycle artifact profile"]
    events = load_jsonl(run_dir / EVENTS_FILENAME)
    records = load_jsonl(run_dir / "results.jsonl")
    identity = expected_event_identity(result, connector, run_id)
    expected = {"phase4_first_byte_before_response_end", "phase4_no_full_response_buffering"}
    passed = {str(record.get("case_id")) for record in records if record.get("status") == "PASS"}
    missing = expected - passed
    if missing:
        return ["first-byte promotion lacks PASS cases: " + ", ".join(sorted(missing))]
    errors: list[str] = []
    for record in records:
        if record.get("case_id") not in expected or record.get("status") != "PASS":
            continue
        candidates = matching_events(
            events,
            record.get("expected_rule_id"),
            identity,
            record_transaction_ids(record),
        )
        if not any(
            event.get("first_byte_before_response_end") is True
            and event.get("upstream_response_finished_at_first_byte") is False
            and event.get("upstream_paused") is True
            and isinstance(event.get("first_chunk_size"), int)
            and event.get("first_chunk_size", 0) > 0
            for event in candidates
        ):
            errors.append(f"{record.get('case_id')}: missing synchronized first-byte event metadata")
    return errors


def no_buffer_errors(
    run_dir: Path,
    manifest: dict[str, Any],
    result: dict[str, Any],
    *,
    connector: str | None = None,
    run_id: str | None = None,
) -> list[str]:
    claimed = capability_state(manifest, "no_full_response_buffering") == "verified"
    claimed = claimed or "no_full_response_buffering" in set(result.get("capabilities_verified") or [])
    if not claimed:
        return []
    events = load_jsonl(run_dir / EVENTS_FILENAME)
    records = load_jsonl(run_dir / "results.jsonl")
    identity = expected_event_identity(result, connector, run_id)
    records = [record for record in records if record.get("case_id") == "phase4_no_full_response_buffering" and record.get("status") == "PASS"]
    if not records:
        return ["no-full-response-buffering promotion lacks a PASS case"]
    for record in records:
        candidates = matching_events(
            events,
            record.get("expected_rule_id"),
            identity,
            record_transaction_ids(record),
        )
        if not any(
            event.get("no_full_response_buffering") is True
            and event.get("first_byte_before_response_end") is True
            and event.get("upstream_response_finished_at_first_byte") is False
            for event in candidates
        ):
            return ["no-full-response-buffering PASS lacks the causal first-byte metadata"]
    return []


def promotion_errors(manifest: dict[str, Any], result: dict[str, Any]) -> list[str]:
    declared = manifest.get("capabilities", {})
    if not isinstance(declared, dict):
        return ["capability manifest has no capabilities object"]
    verified = {name for name, entry in declared.items() if isinstance(entry, dict) and entry.get("state") == "verified"}
    if not verified:
        return []
    if result.get("artifact_profile") != "full_lifecycle":
        return ["verified capability declarations require a full_lifecycle run"]
    runtime_verified = set(result.get("capabilities_verified") or [])
    missing = verified - runtime_verified
    if missing:
        return ["verified capabilities lack current host evidence: " + ", ".join(sorted(missing))]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--check",
        required=True,
        choices=("profile", "first-byte", "no-full-buffer", "lifecycle", "transport", "promotion"),
    )
    parser.add_argument(
        "--connectors",
        nargs="+",
        choices=CONNECTORS,
        default=list(CONNECTORS),
        help="connectors whose concrete native full-lifecycle evidence is required",
    )
    args = parser.parse_args(argv)

    errors: list[str] = []
    for connector in args.connectors:
        run_dir = args.evidence_root / connector / args.run_id
        if not run_dir.is_dir():
            errors.append(f"{connector}: missing canonical run: {run_dir}")
            continue
        try:
            manifest = load_json(args.connector_root / "connectors" / connector / "capabilities.json")
            result = load_json(run_dir / "result.json")
            connector_errors = profile_errors(result, connector)
            if args.check == "first-byte":
                connector_errors += first_byte_errors(
                    run_dir, manifest, result, connector=connector, run_id=args.run_id,
                )
            elif args.check == "no-full-buffer":
                connector_errors += no_buffer_errors(
                    run_dir, manifest, result, connector=connector, run_id=args.run_id,
                )
            elif args.check == "lifecycle":
                connector_errors += lifecycle_errors(run_dir, connector, result)
            elif args.check == "transport":
                connector_errors += transport_artifact_errors(run_dir, connector)
            else:
                connector_errors += promotion_errors(manifest, result)
                connector_errors += first_byte_errors(
                    run_dir, manifest, result, connector=connector, run_id=args.run_id,
                )
                connector_errors += no_buffer_errors(
                    run_dir, manifest, result, connector=connector, run_id=args.run_id,
                )
                connector_errors += lifecycle_errors(run_dir, connector, result)
                connector_errors += transport_artifact_errors(run_dir, connector)
            errors.extend(f"{connector}: {error}" for error in connector_errors)
        except (OSError, ValueError) as exc:
            errors.append(f"{connector}: cannot read canonical evidence: {exc}")
    if errors:
        for error in errors:
            print(f"full-lifecycle-evidence: FAIL: {error}")
        return 1
    print(f"full-lifecycle-evidence: PASS ({args.check}; no unsupported promotion claims)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
