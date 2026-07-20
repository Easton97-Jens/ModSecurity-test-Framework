#!/usr/bin/env python3
"""Validate causal, payload-free transport-hardening evidence.

The checker is intentionally non-promoting: an inventory sidecar can explain
what a host observed, but only a live canonical PASS that is causally bound to
one event, one observation, and one lifecycle record can use it as evidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


FRAMEWORK_ROOT = Path(__file__).resolve().parents[3]
RUNNER_ROOT = FRAMEWORK_ROOT / "tests" / "runners"
CATALOG_ROOT = FRAMEWORK_ROOT / "ci" / "checks" / "catalog"
for path in (CATALOG_ROOT, RUNNER_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import no_crs_baseline as no_crs  # noqa: E402


BASE_CHECKS = (
    "schema",
    "completeness",
    "capability",
    "claim-policy",
    "layout",
    "body-payload",
    "protocol-client",
    "status",
)
REQUIRED_TRANSPORT_ARTIFACTS = tuple(no_crs.TRANSPORT_HARDENING_ARTIFACT_PATHS)
REQUIRED_ENGINE_ARTIFACTS = ("transaction_counts", "lifecycle_counters")
STRICT_CLIENT_RESULTS_HTTP1 = {
    "premature_eof",
    "tcp_reset",
    "incomplete_content_length",
    "chunked_response_aborted",
}


def _load_object(path: Path, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = no_crs.load_json(path)
    except Exception as exc:
        return None, [f"{label}: cannot read JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{label}: must be a JSON object"]
    return payload, []


def _load_jsonl(path: Path, label: str) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        return no_crs.read_jsonl(path), []
    except Exception as exc:
        return [], [f"{label}: cannot read JSONL: {exc}"]


def _canonical_base_errors(run_dir: Path, connector: str) -> list[str]:
    capabilities_path = run_dir / "inventory" / "capabilities.json"
    try:
        capabilities = no_crs.load_capability_manifest(capabilities_path, connector)
    except Exception as exc:
        return [f"inventory/capabilities.json: {exc}"]
    return no_crs.validate_run(run_dir, connector, capabilities, BASE_CHECKS)


def _artifact_path(
    run_dir: Path,
    manifest: Mapping[str, Any],
    name: str,
    *,
    required: bool,
) -> tuple[Path | None, list[str]]:
    expected_path = (
        no_crs.TRANSPORT_HARDENING_ARTIFACT_PATHS.get(name)
        or no_crs.ENGINE_LIFECYCLE_ARTIFACT_PATHS.get(name)
    )
    if expected_path is None:
        return None, [f"unsupported transport artifact name: {name}"]
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return None, ["manifest artifacts must be an object"]
    entry = artifacts.get(name)
    if not isinstance(entry, Mapping):
        return None, [f"manifest is missing transport artifact: {name}"] if required else []
    if entry.get("path") != expected_path:
        return None, [f"transport artifact {name} must use {expected_path}"]
    if entry.get("state") != "produced":
        return None, [f"transport artifact {name} must be produced"] if required else []
    path = run_dir / expected_path
    if path.is_symlink() or not path.is_file():
        return None, [f"transport artifact {name} is missing or unsafe"]
    expected_digest = entry.get("sha256")
    if expected_digest and expected_digest != no_crs.sha256_file(path):
        return None, [f"transport artifact {name} checksum mismatch"]
    return path, []


def _identity_errors(
    payload: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    label: str,
) -> list[str]:
    errors: list[str] = []
    for field in ("connector", "integration_mode", "run_id"):
        if payload.get(field) != manifest.get(field):
            errors.append(f"{label}.{field} does not match canonical run")
    return errors


def _schema_errors(
    payload: object,
    schema_name: str,
    *,
    label: str,
) -> list[str]:
    try:
        schema = no_crs.load_json(
            FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline" / schema_name
        )
    except Exception as exc:
        return [f"{label}: cannot load checked-in schema: {exc}"]
    if not isinstance(schema, Mapping):
        return [f"{label}: checked-in schema must be an object"]
    errors = no_crs.json_schema_errors(payload, schema, root_schema=schema, location=label)
    errors.extend(no_crs.forbidden_payload_errors(payload, label))
    return errors


def _catalog_by_id() -> dict[str, Mapping[str, Any]]:
    return {
        str(case.get("case_id") or ""): case
        for case in no_crs.catalog_cases(no_crs.load_catalog())
    }


def _is_transport_case(record: Mapping[str, Any], case: Mapping[str, Any] | None) -> bool:
    if case and case.get("transport_hardening") is True:
        return True
    group = str((case or record).get("group") or "")
    # Existing full-lifecycle transport cases predate the explicit catalog
    # marker.  Retain them under the same evidence boundary.
    return group.startswith("full-lifecycle-transport")


def _transport_passes(
    records: Sequence[Mapping[str, Any]],
    catalog: Mapping[str, Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any] | None]]:
    return [
        (record, catalog.get(str(record.get("case_id") or "")))
        for record in records
        if record.get("status") == "PASS"
        and record.get("live_executed") is True
        and _is_transport_case(record, catalog.get(str(record.get("case_id") or "")))
    ]


def _rule_key(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.isdigit():
        return str(int(value))
    return None


def _nonempty_token(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _strict_case(record: Mapping[str, Any]) -> bool:
    return (
        str(record.get("expected_result") or "") == "connection_aborted_strict"
        or str(record.get("case_id") or "").startswith("phase4_strict_")
    )


def _transport_record_identity_errors(record: Mapping[str, Any]) -> list[str]:
    case_id = str(record.get("case_id") or "")
    errors: list[str] = []
    transport_case_id = record.get("transport_case_id")
    if not _nonempty_token(transport_case_id):
        errors.append("transport PASS requires a non-empty transport_case_id")
    elif transport_case_id != case_id:
        errors.append("transport PASS transport_case_id must equal case_id")
    transaction_ids = record.get("transaction_ids")
    if not isinstance(transaction_ids, list) or not transaction_ids or not all(
        _nonempty_token(value) for value in transaction_ids
    ):
        errors.append("transport PASS requires one or more non-empty transaction_ids")
    elif len({str(value) for value in transaction_ids}) != len(transaction_ids):
        errors.append("transport PASS transaction_ids must be unique")
    for field in ("requested_action", "actual_action", "transport_result"):
        if record.get(field) is None:
            errors.append(f"transport PASS requires {field}")
    if record.get("connection_id") is None and record.get("stream_id") is None:
        errors.append("transport PASS requires connection_id or stream_id")
    return errors


def _record_run_context_errors(
    record: Mapping[str, Any], manifest: Mapping[str, Any],
) -> list[str]:
    case_id = str(record.get("case_id") or "")
    errors: list[str] = []
    for field in ("connector", "integration_mode", "run_id"):
        if record.get(field) != manifest.get(field):
            errors.append(f"{case_id}: case result {field} does not match canonical run")
    return errors


def _event_run_context_errors(case_id: str, event: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    errors = []
    for field in ("connector", "integration_mode", "run_id"):
        if event.get(field) != manifest.get(field):
            errors.append(f"{case_id}: event {field} does not match canonical run")
    return errors


def _event_correlation_errors(
    case_id: str,
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    transaction_id: str,
) -> list[str]:
    errors = []
    if event.get("transaction_id") != transaction_id:
        errors.append(f"{case_id}: event transaction_id does not match case result")
    if event.get("transport_case_id") != record.get("transport_case_id"):
        errors.append(f"{case_id}: event transport_case_id does not match case result")
    if event.get("phase") != record.get("phase"):
        errors.append(f"{case_id}: event phase does not match case result")
    return errors


def _event_identity_errors(case_id: str, record: Mapping[str, Any], event: Mapping[str, Any]) -> list[str]:
    errors = []
    for field in ("event", "message_id"):
        if not _nonempty_token(event.get(field)):
            errors.append(f"{case_id}: event requires a non-empty {field}")
    event_rule = _rule_key(event.get("rule_id"))
    if event_rule is None:
        errors.append(f"{case_id}: event requires a concrete rule_id")
    elif event_rule not in {_rule_key(value) for value in record.get("observed_rule_ids", [])}:
        errors.append(f"{case_id}: event rule_id is absent from case result")
    expected_rule = record.get("expected_rule_id")
    if expected_rule is not None and event_rule != _rule_key(expected_rule):
        errors.append(f"{case_id}: event rule_id does not match expected_rule_id")
    for field in ("requested_action", "actual_action", "transport_result"):
        if event.get(field) != record.get(field):
            errors.append(f"{case_id}: event {field} does not match case result")
    for field in ("connection_id", "stream_id", "barrier_id"):
        value = record.get(field)
        if value is not None and event.get(field) != value:
            errors.append(f"{case_id}: event {field} does not match case result")
    return errors


def _event_errors(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    transaction_id: str,
) -> list[str]:
    case_id = str(record.get("case_id") or "")
    return (
        _event_run_context_errors(case_id, event, manifest)
        + _event_correlation_errors(case_id, record, event, transaction_id)
        + _event_identity_errors(case_id, record, event)
    )


def _observation_canonical_errors(
    case_id: str,
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    observation: Mapping[str, Any],
    transaction_id: str,
) -> list[str]:
    errors = []
    for field, expected in (
        ("case_id", case_id),
        ("transport_case_id", record.get("transport_case_id")),
        ("transaction_id", transaction_id),
        ("phase", record.get("phase")),
        ("event", event.get("event")),
        ("message_id", event.get("message_id")),
        ("requested_action", record.get("requested_action")),
        ("actual_action", record.get("actual_action")),
        ("transport_result", record.get("transport_result")),
    ):
        if observation.get(field) != expected:
            errors.append(f"{case_id}: observation {field} does not match canonical evidence")
    if _rule_key(observation.get("rule_id")) != _rule_key(event.get("rule_id")):
        errors.append(f"{case_id}: observation rule_id does not match event")
    record_protocol = record.get("negotiated_protocol") or record.get("downstream_protocol")
    if record_protocol is not None and observation.get("protocol") != record_protocol:
        errors.append(f"{case_id}: observation protocol does not match case result")
    return errors


def _observation_identity_errors(
    case_id: str,
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> list[str]:
    errors = []
    identity_pairs = (
        ("connection_id", record.get("connection_id")),
        ("stream_id", record.get("stream_id")),
        ("barrier_id", record.get("barrier_id")),
    )
    for field, expected in identity_pairs:
        if expected is not None and observation.get(field) != expected:
            errors.append(f"{case_id}: observation {field} does not match case result")
        if observation.get(field) is not None and event.get(field) != observation.get(field):
            errors.append(f"{case_id}: observation {field} does not match event")
    if observation.get("connection_id") is None and observation.get("stream_id") is None:
        errors.append(f"{case_id}: observation requires connection_id or stream_id")
    return errors


def _observation_privacy_errors(case_id: str, observation: Mapping[str, Any]) -> list[str]:
    errors = []
    if observation.get("protocol") == "h3":
        connection_id = observation.get("connection_id")
        if connection_id is not None and not no_crs.is_hashed_connection_id(connection_id):
            errors.append(f"{case_id}: observation may not retain a raw H3 connection_id")
    if observation.get("eos_seen") is not None and observation.get("eos_seen") != observation.get("eos_received"):
        errors.append(f"{case_id}: observation eos_seen disagrees with eos_received")
    reset_code = observation.get("reset_code")
    stream_reset_code = observation.get("stream_reset_code")
    if reset_code is not None and stream_reset_code is not None and reset_code != stream_reset_code:
        errors.append(f"{case_id}: reset_code disagrees with stream_reset_code")
    return errors


def _observation_errors(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    transaction_id: str,
) -> list[str]:
    case_id = str(record.get("case_id") or "")
    return (
        _observation_canonical_errors(case_id, record, event, observation, transaction_id)
        + _observation_identity_errors(case_id, record, event, observation)
        + _observation_privacy_errors(case_id, observation)
    )


def _strict_common_errors(case_id: str, record: Mapping[str, Any], observation: Mapping[str, Any]) -> list[str]:
    errors = []
    if observation.get("response_committed") is not True:
        errors.append(f"{case_id}: strict evidence requires response_committed=true")
    if observation.get("first_byte_received") is not True:
        errors.append(f"{case_id}: strict evidence requires first_byte_received=true")
    if observation.get("eos_received") is not False:
        errors.append(f"{case_id}: strict evidence requires eos_received=false")
    if observation.get("host_survived") is not True:
        errors.append(f"{case_id}: strict evidence requires host_survived=true")
    if observation.get("followup_request_result") != "completed":
        errors.append(f"{case_id}: strict evidence requires a completed independent follow-up")
    if record.get("actual_status") == 403 or record.get("visible_http_status") == 403:
        errors.append(f"{case_id}: strict evidence must not claim a post-commit HTTP 403")
    return errors


def _strict_http1_errors(case_id: str, record: Mapping[str, Any], observation: Mapping[str, Any]) -> list[str]:
    errors = []
    if record.get("actual_action") != "abort_connection":
        errors.append(f"{case_id}: HTTP/1 strict evidence requires actual_action=abort_connection")
    if record.get("transport_result") != "connection_aborted":
        errors.append(f"{case_id}: HTTP/1 strict evidence requires transport_result=connection_aborted")
    if observation.get("client_result") not in STRICT_CLIENT_RESULTS_HTTP1:
        errors.append(f"{case_id}: HTTP/1 strict evidence lacks a client-observed abort")
    return errors


def _strict_h2_or_h3_errors(case_id: str, record: Mapping[str, Any], observation: Mapping[str, Any]) -> list[str]:
    errors = []
    if record.get("actual_action") != "stream_reset":
        errors.append(f"{case_id}: H2/H3 strict evidence requires actual_action=stream_reset")
    if record.get("transport_result") != "stream_reset":
        errors.append(f"{case_id}: H2/H3 strict evidence requires transport_result=stream_reset")
    if observation.get("client_result") != "stream_reset":
        errors.append(f"{case_id}: H2/H3 strict evidence requires client_result=stream_reset")
    if observation.get("stream_reset") is not True:
        errors.append(f"{case_id}: H2/H3 strict evidence requires stream_reset=true")
    if observation.get("reset_code") is None and observation.get("stream_reset_code") is None:
        errors.append(f"{case_id}: H2/H3 strict evidence requires a reset code")
    return errors


def _strict_errors(record: Mapping[str, Any], observation: Mapping[str, Any]) -> list[str]:
    if not _strict_case(record):
        return []
    case_id = str(record.get("case_id") or "")
    errors = _strict_common_errors(case_id, record, observation)
    protocol = observation.get("protocol")
    if protocol == "http1":
        errors.extend(_strict_http1_errors(case_id, record, observation))
    elif protocol in {"h2", "h2c", "h3"}:
        errors.extend(_strict_h2_or_h3_errors(case_id, record, observation))
    else:
        errors.append(f"{case_id}: strict evidence uses unsupported protocol {protocol!r}")
    return errors


def _lifecycle_record_errors(record: Mapping[str, Any], *, label: str) -> list[str]:
    errors: list[str] = []
    started = record.get("transaction_started")
    finished = record.get("transaction_finished")
    destroyed = record.get("transaction_destroyed")
    if not isinstance(started, int) or not isinstance(finished, int) or not isinstance(destroyed, int):
        return [f"{label}: lifecycle singleton counters must be integers"]
    if finished > started:
        errors.append(f"{label}: transaction_finished exceeds transaction_started")
    if destroyed > finished:
        errors.append(f"{label}: transaction_destroyed exceeds transaction_finished")
    for field in (
        "request_body_finished", "response_body_finished", "eos_seen", "intentional_abort",
        "client_disconnect", "upstream_disconnect", "stream_reset", "timeout",
    ):
        value = record.get(field)
        if isinstance(value, int) and value > started:
            errors.append(f"{label}: {field} requires a started transaction")
    return errors


REQUIRED_LIFECYCLE_COUNTERS = (
    "transactions_started", "transactions_finished", "transactions_destroyed",
    "request_body_finishes", "response_body_finishes", "interventions_seen",
    "intentional_aborts", "unexpected_engine_errors",
)


def _required_counter_errors(counters: Mapping[str, Any]) -> list[str]:
    errors = []
    for field in REQUIRED_LIFECYCLE_COUNTERS:
        if not isinstance(counters.get(field), int) or counters[field] < 0:
            errors.append(f"lifecycle_counters.{field} must be a non-negative integer")
    return errors


def _counter_value(record: Mapping[str, Any], field: str) -> int:
    value = record.get(field, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _bound_counter_expectations(lifecycle_records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "client_disconnects": sum(_counter_value(record, "client_disconnect") for record in lifecycle_records),
        "upstream_disconnects": sum(_counter_value(record, "upstream_disconnect") for record in lifecycle_records),
        "stream_resets": sum(_counter_value(record, "stream_reset") for record in lifecycle_records),
        "timeouts": sum(_counter_value(record, "timeout") for record in lifecycle_records),
        "short_writes": sum(_counter_value(record, "short_writes") for record in lifecycle_records),
        "write_would_block": sum(_counter_value(record, "write_would_block") for record in lifecycle_records),
        "cleanup_normal": sum(record.get("cleanup_reason") == "normal" for record in lifecycle_records),
        "cleanup_cancel": sum(record.get("cleanup_reason") in {"cancelled", "client_disconnected", "upstream_disconnected"} for record in lifecycle_records),
        "cleanup_abort": sum(record.get("cleanup_reason") in {"strict_abort", "stream_reset"} for record in lifecycle_records),
        "intentional_aborts": sum(_counter_value(record, "intentional_abort") for record in lifecycle_records),
    }


def _counter_lower_bounds(lifecycle_records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "transactions_started": sum(_counter_value(record, "transaction_started") for record in lifecycle_records),
        "transactions_finished": sum(_counter_value(record, "transaction_finished") for record in lifecycle_records),
        "transactions_destroyed": sum(_counter_value(record, "transaction_destroyed") for record in lifecycle_records),
        "request_body_finishes": sum(_counter_value(record, "request_body_finished") for record in lifecycle_records),
        "response_body_finishes": sum(_counter_value(record, "response_body_finished") for record in lifecycle_records),
        "intentional_aborts": sum(_counter_value(record, "intentional_abort") for record in lifecycle_records),
    }


def _counter_errors(
    counters: Mapping[str, Any],
    lifecycle_records: Sequence[Mapping[str, Any]],
    *,
    require_bound_counts: bool,
) -> list[str]:
    errors = _required_counter_errors(counters)
    if errors:
        return errors
    if not (
        counters["transactions_started"] >= counters["transactions_finished"]
        >= counters["transactions_destroyed"]
    ):
        errors.append("lifecycle_counters transaction lifecycle is inconsistent")
    if not require_bound_counts:
        return errors
    if counters.get("transport_counters_bound") is not True:
        errors.append("transport PASS requires lifecycle_counters.transport_counters_bound=true")
        return errors
    for field, expected_value in _bound_counter_expectations(lifecycle_records).items():
        if counters.get(field) != expected_value:
            errors.append(
                f"lifecycle_counters.{field}={counters.get(field)!r}, expected {expected_value} from connection-lifecycle"
            )
    # The global lifecycle counters may include non-transport transactions,
    # but they can never be lower than the concrete transport records.
    for field, lower_bound in _counter_lower_bounds(lifecycle_records).items():
        if counters.get(field, -1) < lower_bound:
            errors.append(f"lifecycle_counters.{field} is below connection-lifecycle accounting")
    return errors


def _inventory_paths(
    run_dir: Path,
    manifest: Mapping[str, Any],
    required: bool,
) -> tuple[dict[str, Path | None], list[str]]:
    paths: dict[str, Path | None] = {}
    errors = []
    for name in REQUIRED_TRANSPORT_ARTIFACTS + REQUIRED_ENGINE_ARTIFACTS:
        path, artifact_errors = _artifact_path(run_dir, manifest, name, required=required)
        paths[name] = path
        errors.extend(artifact_errors)
    return paths, errors


def _h3_connection_id_errors(payload: Mapping[str, Any], records_key: str, label: str) -> list[str]:
    records = payload.get(records_key)
    if not isinstance(records, list):
        return []
    errors = []
    for index, record in enumerate(records):
        if isinstance(record, Mapping) and record.get("protocol") == "h3":
            connection_id = record.get("connection_id")
            if connection_id is not None and not no_crs.is_hashed_connection_id(connection_id):
                errors.append(
                    f"{label}.{records_key}[{index}].connection_id: raw H3 connection identifiers are forbidden"
                )
    return errors


def _validated_inventory_object(
    path: Path | None,
    label: str,
    schema_name: str,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, []
    payload, errors = _load_object(path, label)
    if payload is not None:
        errors.extend(_schema_errors(payload, schema_name, label=label))
        errors.extend(_identity_errors(payload, manifest, label=label))
    return payload, errors


def _validated_barrier_events(
    path: Path | None,
    manifest: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    if path is None:
        return [], []
    events, errors = _load_jsonl(path, "barrier-events")
    for index, event in enumerate(events):
        label = f"barrier-events[{index}]"
        errors.extend(no_crs.canonical_event_errors(
            event,
            label,
            str(manifest.get("connector") or ""),
            str(manifest.get("integration_mode") or ""),
        ))
        for field in ("connector", "integration_mode", "run_id"):
            if event.get(field) != manifest.get(field):
                errors.append(f"{label}.{field} does not match canonical run")
    return events, errors


def _engine_inventory_payload(
    path: Path | None,
    name: str,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    if path is None:
        return None, []
    payload, errors = _load_object(path, name)
    if payload is not None and (
        payload.get("schema_version") != 1 or payload.get("connector") != manifest.get("connector")
    ):
        errors.append(f"{name} has invalid identity")
    return payload, errors


def _inventory_errors(
    run_dir: Path,
    manifest: Mapping[str, Any],
    *,
    required: bool,
) -> tuple[
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[dict[str, Any]],
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[str],
]:
    """Read and validate supplemental inventory, returning payloads and errors."""
    paths, errors = _inventory_paths(run_dir, manifest, required)

    observations, observation_errors = _validated_inventory_object(
        paths.get("transport_observations"),
        "transport-observations",
        "transport-observations.schema.json",
        manifest,
    )
    errors.extend(observation_errors)
    if observations is not None:
        errors.extend(_h3_connection_id_errors(observations, "observations", "transport-observations"))

    lifecycle, lifecycle_errors = _validated_inventory_object(
        paths.get("connection_lifecycle"),
        "connection-lifecycle",
        "connection-lifecycle.schema.json",
        manifest,
    )
    errors.extend(lifecycle_errors)
    if lifecycle is not None:
        errors.extend(_h3_connection_id_errors(lifecycle, "records", "connection-lifecycle"))

    _config, config_errors = _validated_inventory_object(
        paths.get("effective_config"),
        "effective-config",
        "effective-config.schema.json",
        manifest,
    )
    errors.extend(config_errors)

    barrier_events, barrier_errors = _validated_barrier_events(paths.get("barrier_events"), manifest)
    errors.extend(barrier_errors)

    counters, counter_errors = _engine_inventory_payload(paths.get("lifecycle_counters"), "lifecycle_counters", manifest)
    errors.extend(counter_errors)
    transaction_counts, transaction_errors = _engine_inventory_payload(
        paths.get("transaction_counts"), "transaction_counts", manifest
    )
    errors.extend(transaction_errors)
    return observations, lifecycle, barrier_events, counters, transaction_counts, errors


def _sidecar_mapping_records(payload: Mapping[str, Any] | None, field: str) -> list[Mapping[str, Any]]:
    records = payload.get(field) if payload else []
    return [item for item in records if isinstance(item, Mapping)] if isinstance(records, list) else []


def _diagnostic_sidecar_errors(
    observations: Mapping[str, Any] | None,
    lifecycle: Mapping[str, Any] | None,
    counters: Mapping[str, Any] | None,
) -> list[str]:
    observation_records = _sidecar_mapping_records(observations, "observations")
    lifecycle_records = _sidecar_mapping_records(lifecycle, "records")
    errors = _counter_errors(
        counters,
        lifecycle_records,
        require_bound_counts=counters.get("transport_counters_bound") is True,
    ) if counters is not None else []
    seen_observation_keys: set[tuple[str, str]] = set()
    for index, observation in enumerate(observation_records):
        label = f"transport-observations[{index}]"
        key = (str(observation.get("case_id") or ""), str(observation.get("transaction_id") or ""))
        if key in seen_observation_keys:
            errors.append(f"{label} duplicates case/transaction correlation {key!r}")
        seen_observation_keys.add(key)
    seen_lifecycle_keys: set[tuple[str, str]] = set()
    for index, lifecycle_record in enumerate(lifecycle_records):
        label = f"connection-lifecycle[{index}]"
        errors.extend(_lifecycle_record_errors(lifecycle_record, label=label))
        key = (
            str(lifecycle_record.get("transport_case_id") or ""),
            str(lifecycle_record.get("transaction_id") or ""),
        )
        if key in seen_lifecycle_keys:
            errors.append(f"{label} duplicates transport/transaction correlation {key!r}")
        seen_lifecycle_keys.add(key)
    return errors


def _transaction_count_ids(transaction_counts: Mapping[str, Any]) -> tuple[set[str], list[str]]:
    count_ids = transaction_counts.get("transaction_ids")
    if not isinstance(count_ids, list) or not all(_nonempty_token(value) for value in count_ids):
        return set(), ["transaction_counts.transaction_ids must contain bounded identifiers"]
    count_id_set = {str(value) for value in count_ids}
    errors = []
    if transaction_counts.get("transactions_observed") != len(count_ids):
        errors.append("transaction_counts does not match its transaction_ids")
    if len(count_id_set) != len(count_ids):
        errors.append("transaction_counts.transaction_ids must be unique")
    return count_id_set, errors


def _indexed_sidecar_errors(
    observation_records: Sequence[Mapping[str, Any]],
    lifecycle_records: Sequence[Mapping[str, Any]],
    count_id_set: set[str],
) -> tuple[dict[tuple[str, str], Mapping[str, Any]], list[str]]:
    errors: list[str] = []
    observation_keys: set[tuple[str, str]] = set()
    for index, observation in enumerate(observation_records):
        key = (str(observation.get("case_id") or ""), str(observation.get("transaction_id") or ""))
        if key in observation_keys:
            errors.append(f"transport-observations[{index}] duplicates case/transaction correlation {key!r}")
        observation_keys.add(key)
    lifecycle_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for index, lifecycle_record in enumerate(lifecycle_records):
        label = f"connection-lifecycle[{index}]"
        errors.extend(_lifecycle_record_errors(lifecycle_record, label=label))
        key = (
            str(lifecycle_record.get("transport_case_id") or ""),
            str(lifecycle_record.get("transaction_id") or ""),
        )
        if key in lifecycle_by_key:
            errors.append(f"{label} duplicates transport/transaction correlation {key!r}")
        lifecycle_by_key[key] = lifecycle_record
        if key[1] not in count_id_set:
            errors.append(f"{label}: transaction_id is absent from transaction_counts")
    return lifecycle_by_key, errors


def _matching_transport_events(
    events: Sequence[Mapping[str, Any]],
    transport_case_id: str,
    transaction_id: str,
) -> list[tuple[int, Mapping[str, Any]]]:
    return [
        (index, event)
        for index, event in enumerate(events)
        if event.get("transport_case_id") == transport_case_id and event.get("transaction_id") == transaction_id
    ]


def _matching_transport_observations(
    observations: Sequence[Mapping[str, Any]],
    case_id: str,
    transport_case_id: str,
    transaction_id: str,
) -> list[Mapping[str, Any]]:
    return [
        observation
        for observation in observations
        if observation.get("case_id") == case_id
        and observation.get("transport_case_id") == transport_case_id
        and observation.get("transaction_id") == transaction_id
    ]


def _lifecycle_observation_errors(
    case_id: str,
    record: Mapping[str, Any],
    observation: Mapping[str, Any],
    lifecycle_record: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    if observation.get("eos_received") != bool(lifecycle_record.get("eos_seen")):
        errors.append(f"{case_id}: lifecycle eos_seen does not match transport observation")
    for observation_field, lifecycle_field in (
        ("client_disconnected", "client_disconnect"),
        ("upstream_disconnected", "upstream_disconnect"),
        ("stream_reset", "stream_reset"),
    ):
        if observation.get(observation_field) is True and lifecycle_record.get(lifecycle_field) != 1:
            errors.append(f"{case_id}: lifecycle {lifecycle_field} does not match transport observation")
    if observation.get("write_result") == "short_write" and lifecycle_record.get("short_writes", 0) < 1:
        errors.append(f"{case_id}: lifecycle short_writes does not match transport observation")
    if observation.get("write_result") == "write_would_block" and lifecycle_record.get("write_would_block", 0) < 1:
        errors.append(f"{case_id}: lifecycle write_would_block does not match transport observation")
    if _strict_case(record) and lifecycle_record.get("intentional_abort") != 1:
        errors.append(f"{case_id}: strict transport evidence requires intentional_abort=1")
    return errors


def _transaction_correlation_errors(
    record: Mapping[str, Any],
    transaction_id: str,
    events: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
    lifecycle_by_key: Mapping[tuple[str, str], Mapping[str, Any]],
    count_id_set: set[str],
    manifest: Mapping[str, Any],
    used_event_indexes: set[int],
    used_observations: set[tuple[str, str]],
    strict_lifecycle_keys: set[tuple[str, str]],
) -> list[str]:
    case_id = str(record.get("case_id") or "")
    transport_case_id = str(record.get("transport_case_id") or "")
    errors = []
    if transaction_id not in count_id_set:
        errors.append(f"{case_id}: transaction_id is absent from transaction_counts")
    matching_events = _matching_transport_events(events, transport_case_id, transaction_id)
    if len(matching_events) != 1:
        return errors + [f"{case_id}: requires exactly one event for transport_case_id/transaction_id"]
    event_index, event = matching_events[0]
    if event_index in used_event_indexes:
        errors.append(f"{case_id}: reuses an event claimed by another transport case")
    used_event_indexes.add(event_index)
    errors.extend(_event_errors(record, event, manifest, transaction_id=transaction_id))
    matching_observations = _matching_transport_observations(observations, case_id, transport_case_id, transaction_id)
    if len(matching_observations) != 1:
        return errors + [f"{case_id}: requires exactly one matching transport observation"]
    observation = matching_observations[0]
    observation_key = (case_id, transaction_id)
    if observation_key in used_observations:
        errors.append(f"{case_id}: reuses a transport observation")
    used_observations.add(observation_key)
    errors.extend(_observation_errors(record, event, observation, transaction_id=transaction_id))
    errors.extend(_strict_errors(record, observation))
    lifecycle_key = (transport_case_id, transaction_id)
    lifecycle_record = lifecycle_by_key.get(lifecycle_key)
    if lifecycle_record is None:
        return errors + [f"{case_id}: requires a matching connection-lifecycle record"]
    errors.extend(_lifecycle_observation_errors(case_id, record, observation, lifecycle_record))
    if _strict_case(record):
        strict_lifecycle_keys.add(lifecycle_key)
    return errors


def _pass_correlation_errors(
    passes: Sequence[tuple[Mapping[str, Any], Mapping[str, Any] | None]],
    events: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
    lifecycle_by_key: Mapping[tuple[str, str], Mapping[str, Any]],
    count_id_set: set[str],
    manifest: Mapping[str, Any],
) -> tuple[set[tuple[str, str]], list[str]]:
    errors: list[str] = []
    used_event_indexes: set[int] = set()
    used_observations: set[tuple[str, str]] = set()
    strict_lifecycle_keys: set[tuple[str, str]] = set()
    for record, _case in passes:
        case_id = str(record.get("case_id") or "")
        errors.extend(_record_run_context_errors(record, manifest))
        errors.extend(f"{case_id}: {error}" for error in _transport_record_identity_errors(record))
        transaction_ids = record.get("transaction_ids") if isinstance(record.get("transaction_ids"), list) else []
        for raw_transaction_id in transaction_ids:
            errors.extend(_transaction_correlation_errors(
                record,
                str(raw_transaction_id),
                events,
                observations,
                lifecycle_by_key,
                count_id_set,
                manifest,
                used_event_indexes,
                used_observations,
                strict_lifecycle_keys,
            ))
    return strict_lifecycle_keys, errors


def _unbound_lifecycle_errors(
    lifecycle_by_key: Mapping[tuple[str, str], Mapping[str, Any]],
    passes: Sequence[tuple[Mapping[str, Any], Mapping[str, Any] | None]],
    observations: Sequence[Mapping[str, Any]],
    strict_lifecycle_keys: set[tuple[str, str]],
) -> list[str]:
    pass_lifecycle_keys = {
        (str(record.get("transport_case_id") or ""), str(transaction_id))
        for record, _case in passes
        for transaction_id in (record.get("transaction_ids", []) if isinstance(record.get("transaction_ids"), list) else [])
    }
    observations_by_lifecycle_key = {
        (str(observation.get("transport_case_id") or ""), str(observation.get("transaction_id") or "")): observation
        for observation in observations
    }
    errors = []
    for key, lifecycle_record in lifecycle_by_key.items():
        if lifecycle_record.get("intentional_abort") == 1 and key not in strict_lifecycle_keys:
            errors.append("connection-lifecycle intentional_abort lacks a matching strict transport event")
        if lifecycle_record.get("stream_reset") == 1:
            observation = observations_by_lifecycle_key.get(key)
            if key not in pass_lifecycle_keys or observation is None or observation.get("transport_result") != "stream_reset":
                errors.append("connection-lifecycle stream_reset lacks a matching transport case")
    return errors


def _barrier_event_errors(
    record: Mapping[str, Any],
    transaction_id: object,
    barrier_events: Sequence[Mapping[str, Any]],
) -> list[str]:
    case_id = str(record.get("case_id") or "")
    transport_case_id = record.get("transport_case_id")
    candidates = [
        event for event in barrier_events
        if event.get("transport_case_id") == transport_case_id and event.get("transaction_id") == transaction_id
    ]
    if len(candidates) != 1:
        return [f"{case_id}: requires exactly one matching barrier event"]
    barrier_event = candidates[0]
    errors = []
    if record.get("barrier_id") is not None and barrier_event.get("barrier_id") != record.get("barrier_id"):
        errors.append(f"{case_id}: barrier event barrier_id does not match case result")
    for field in ("client_first_byte_received", "first_byte_before_response_end", "response_committed"):
        if barrier_event.get(field) is not True:
            errors.append(f"{case_id}: barrier event requires {field}=true")
    if barrier_event.get("upstream_eos_sent_at_first_byte") is not False:
        errors.append(f"{case_id}: barrier event requires upstream_eos_sent_at_first_byte=false")
    return errors


def _barrier_binding_errors(
    passes: Sequence[tuple[Mapping[str, Any], Mapping[str, Any] | None]],
    barrier_events: Sequence[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for record, _case in passes:
        expected_result = str(record.get("expected_result") or "")
        requires_barrier = record.get("barrier_id") is not None or expected_result in {
            "first_byte_before_response_end", "no_full_response_buffering"
        }
        if not requires_barrier:
            continue
        transaction_ids = record.get("transaction_ids", []) if isinstance(record.get("transaction_ids"), list) else []
        for transaction_id in transaction_ids:
            errors.extend(_barrier_event_errors(record, transaction_id, barrier_events))
    return errors


def transport_hardening_errors(run_dir: Path) -> list[str]:
    result, result_errors = _load_object(run_dir / "result.json", "result.json")
    manifest, manifest_errors = _load_object(run_dir / "manifest.json", "manifest.json")
    errors = result_errors + manifest_errors
    if result is None or manifest is None:
        return errors
    if manifest.get("artifact_profile") != no_crs.FULL_LIFECYCLE_ARTIFACT_PROFILE:
        return errors + ["transport-hardening checks require artifact_profile=full_lifecycle"]
    connector = str(manifest.get("connector") or "")
    errors.extend(_canonical_base_errors(run_dir, connector))
    records, record_errors = _load_jsonl(run_dir / "results.jsonl", "results.jsonl")
    events, event_errors = _load_jsonl(run_dir / "events.jsonl", "events.jsonl")
    errors.extend(record_errors)
    errors.extend(event_errors)
    catalog = _catalog_by_id()
    passes = _transport_passes(records, catalog)

    observations, lifecycle, barrier_events, counters, transaction_counts, inventory_errors = _inventory_errors(
        run_dir, manifest, required=bool(passes)
    )
    errors.extend(inventory_errors)
    # With no real transport PASS, supplied sidecars are diagnostic only.  We
    # still validate their schemas, local lifecycle cardinality, duplicate
    # correlation keys, and any declared aggregate accounting; however, an
    # abort/reset observed by a host must not be rejected just because it has
    # no canonical client-visible PASS to bind it to.  It remains
    # non-promoting because ``passes`` is empty and the corresponding result
    # stays NOT_EXECUTED.
    if not passes:
        errors.extend(_diagnostic_sidecar_errors(observations, lifecycle, counters))
        return errors
    if observations is None or lifecycle is None or counters is None or transaction_counts is None:
        return errors

    raw_observations = observations.get("observations")
    raw_lifecycle = lifecycle.get("records")
    if not isinstance(raw_observations, list) or not isinstance(raw_lifecycle, list):
        return errors + ["transport sidecars have invalid records arrays"]
    observation_records = [item for item in raw_observations if isinstance(item, Mapping)]
    lifecycle_records = [item for item in raw_lifecycle if isinstance(item, Mapping)]
    errors.extend(_counter_errors(counters, lifecycle_records, require_bound_counts=True))

    count_id_set, count_errors = _transaction_count_ids(transaction_counts)
    errors.extend(count_errors)
    lifecycle_by_key, sidecar_errors = _indexed_sidecar_errors(
        observation_records, lifecycle_records, count_id_set
    )
    errors.extend(sidecar_errors)
    strict_lifecycle_keys, correlation_errors = _pass_correlation_errors(
        passes,
        events,
        observation_records,
        lifecycle_by_key,
        count_id_set,
        manifest,
    )
    errors.extend(correlation_errors)
    errors.extend(_unbound_lifecycle_errors(
        lifecycle_by_key,
        passes,
        observation_records,
        strict_lifecycle_keys,
    ))
    errors.extend(_barrier_binding_errors(passes, barrier_events))
    return errors


CHECKS = {"all": transport_hardening_errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--check", choices=sorted(CHECKS), default="all")
    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir)
    errors = CHECKS[args.check](run_dir)
    if errors:
        for error in errors:
            print(f"transport-hardening-evidence: {error}", file=sys.stderr)
        return 1
    print(f"transport-hardening-evidence: PASS ({run_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
