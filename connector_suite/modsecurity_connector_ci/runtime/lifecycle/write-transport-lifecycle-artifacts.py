#!/usr/bin/env python3
"""Create payload-free transport-lifecycle inventory artifacts.

The artifacts are derived only from already-normalized canonical events.  They
are inventory: their presence never turns a capability into a PASS.  In
particular, an absent client observation is written as ``not_observed`` rather
than inferred from an internal callback or a completed host process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import sys
from typing import Any, Iterable




from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, prepare_verified_runtime_artifact_root, runtime_artifact_path, runtime_or_source_artifact_path, write_runtime_artifact_text_atomic


CONNECTOR_INTEGRATION_MODES = {
    "apache": "native-httpd-module",
    "nginx": "native-nginx-http-module",
    "haproxy": "native-htx-filter",
    "envoy": "ext_proc",
    "traefik": "native-traefik-middleware",
    "lighttpd": "patched-native-lighttpd",
}
CANONICAL_PROTOCOLS = {"http1", "h2", "h2c", "h3"}
CANONICAL_TRANSPORT_RESULTS = {
    "completed",
    "http_status",
    "log_only",
    "connection_aborted",
    "stream_reset",
    "client_cancelled",
    "client_disconnected",
    "upstream_reset",
    "upstream_disconnected",
    "timeout",
    "short_write",
    "write_would_block",
    "engine_error",
    "host_error",
}
CLIENT_RESULTS = {
    "completed", "premature_eof", "tcp_reset", "incomplete_content_length",
    "chunked_response_aborted", "stream_reset", "client_cancelled",
    "client_disconnected", "timeout", "short_write", "write_would_block",
    "engine_error", "host_error", "not_observable",
}
FOLLOWUP_RESULTS = {"completed", "failed", "not_attempted", "not_observable"}
REQUESTED_ACTIONS = {"deny", "redirect", "drop", "log_only", "abort_connection"}
ACTUAL_ACTIONS = {"deny", "redirect", "log_only", "abort_connection", "stream_reset"}
RESET_BY = {"client", "upstream", "engine", "host", "strict_intervention", "timeout"}
TIMEOUT_STAGES = {"engine", "request_body", "response_body", "upstream", "client_idle", "before_commit", "after_commit"}
WRITE_RESULTS = {"completed", "short_write", "write_would_block", "engine_error", "host_error"}
CLEANUP_REASONS = {"normal", "cancelled", "client_disconnected", "upstream_disconnected", "stream_reset", "timeout", "engine_error", "host_error", "strict_abort"}
FORBIDDEN_KEYS = {
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


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"events must be a regular file: {path}")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"events line {number} is not JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"events line {number} must be an object")
        forbidden = sorted(FORBIDDEN_KEYS.intersection(record))
        if forbidden:
            raise ValueError(
                f"events line {number} contains forbidden payload metadata: "
                + ", ".join(forbidden)
            )
        records.append(record)
    return records


def write_json(runtime_root: Path, path: Path, value: object, label: str) -> None:
    write_runtime_artifact_text_atomic(
        runtime_root,
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        label,
    )


def write_jsonl(runtime_root: Path, path: Path, values: Iterable[object], label: str) -> None:
    write_runtime_artifact_text_atomic(
        runtime_root,
        path,
        "".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
        label,
    )


def bounded_token(value: object, maximum: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        return None
    if not all(character.isascii() and (character.isalnum() or character in ":._-") for character in normalized):
        return None
    return normalized


def canonical_protocol(event: dict[str, Any]) -> str | None:
    for name in ("negotiated_protocol", "downstream_protocol", "transport_protocol"):
        value = str(event.get(name) or "").strip().lower()
        if value == "http2":
            value = "h2"
        if value in CANONICAL_PROTOCOLS:
            return value
    return None


def canonical_transport_result(event: dict[str, Any]) -> str | None:
    value = str(event.get("transport_result") or "").strip().lower().replace("-", "_")
    if value in CANONICAL_TRANSPORT_RESULTS:
        return value
    return None


def normalized_enum(value: object, allowed: set[str]) -> str | None:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return normalized if normalized in allowed else None


def phase_number(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 5:
        return value
    aliases = {"connection": 0, "request_headers": 1, "request_body": 2,
               "response_headers": 3, "response_body": 4}
    return aliases.get(str(value or "").strip().lower())


def normalized_rule_id(value: object) -> int | str | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 9_999_999_999:
        return value
    token = bounded_token(value, maximum=10)
    return token if token is not None and token.isdecimal() else None


def transport_identity(event: dict[str, Any]) -> dict[str, object] | None:
    protocol = canonical_protocol(event)
    transport_case_id = bounded_token(event.get("transport_case_id"))
    transaction_id = bounded_token(event.get("transaction_id"), maximum=256)
    phase = phase_number(event.get("phase"))
    event_name = bounded_token(event.get("event"))
    message_id = bounded_token(event.get("message_id"))
    if None in {protocol, transport_case_id, transaction_id, phase, event_name, message_id}:
        return None
    # Canonical events deliberately do not persist the catalog case ID.  A
    # transport PASS is only valid when its explicit transport_case_id equals
    # that catalog ID (enforced by the Framework).  Reusing the bounded
    # transport token here preserves that asserted relation without guessing
    # from a fixture name or an unrelated raw ``case_id`` field.
    return {
        "protocol": protocol,
        "case_id": transport_case_id,
        "transport_case_id": transport_case_id,
        "transaction_id": transaction_id,
        "rule_id": normalized_rule_id(event.get("rule_id")),
        "phase": phase,
        "event": event_name,
        "message_id": message_id,
    }


def optional_reset_code(value: object) -> int | str | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 4_611_686_018_427_387_903:
        return value
    return bounded_token(value, maximum=64)


def optional_stream_id(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 4_611_686_018_427_387_903 else None


def safe_connection_id(protocol: object, value: object) -> str | None:
    """Keep HTTP/3 connection identity only when it is a non-reversible hash."""

    connection_id = bounded_token(value)
    if connection_id is None:
        return None
    if protocol == "h3" and re.fullmatch(r"sha256:[0-9a-f]{16,64}", connection_id) is None:
        return None
    return connection_id


def observation_from_event(event: dict[str, Any]) -> dict[str, object] | None:
    identity = transport_identity(event)
    host_survived = event.get("host_survived")
    if identity is None or not isinstance(host_survived, bool):
        # Existing generic lifecycle events do not carry client-owned case
        # identity or a follow-up observation.  Do not invent either.
        return None
    client_result = normalized_enum(event.get("client_result"), CLIENT_RESULTS) or "not_observable"
    followup = normalized_enum(event.get("followup_request_result"), FOLLOWUP_RESULTS) or "not_observable"
    result = canonical_transport_result(event) or "not_observable"
    requested = normalized_enum(event.get("requested_action"), REQUESTED_ACTIONS)
    actual = normalized_enum(event.get("actual_action"), ACTUAL_ACTIONS)
    output: dict[str, object] = {
        **identity,
        "requested_action": requested,
        "actual_action": actual,
        "response_committed": event.get("response_committed") is True,
        "first_byte_received": event.get("client_first_byte_received") is True,
        "eos_received": event.get("eos_seen") is True,
        "client_result": client_result,
        "transport_result": result,
        "host_survived": host_survived,
        "followup_request_result": followup,
        "connection_id": safe_connection_id(identity["protocol"], event.get("connection_id")),
        "stream_id": optional_stream_id(event.get("stream_id")),
        "barrier_id": bounded_token(event.get("barrier_id")),
        "connection_reused": event.get("connection_reused") if isinstance(event.get("connection_reused"), bool) else None,
        "eos_seen": event.get("eos_seen") if isinstance(event.get("eos_seen"), bool) else None,
        "client_disconnected": event.get("client_disconnected") if isinstance(event.get("client_disconnected"), bool) else None,
        "upstream_disconnected": event.get("upstream_disconnected") if isinstance(event.get("upstream_disconnected"), bool) else None,
        "cancelled": event.get("cancelled") if isinstance(event.get("cancelled"), bool) else None,
        "stream_reset": event.get("stream_reset") if isinstance(event.get("stream_reset"), bool) else None,
        "reset_by": normalized_enum(event.get("reset_by"), RESET_BY),
        "reset_code": optional_reset_code(event.get("reset_code")),
        "stream_reset_code": optional_reset_code(event.get("stream_reset_code")),
        "timeout_stage": normalized_enum(event.get("timeout_stage"), TIMEOUT_STAGES),
        "write_result": normalized_enum(event.get("write_result"), WRITE_RESULTS),
        "cleanup_reason": normalized_enum(event.get("cleanup_reason"), CLEANUP_REASONS),
    }
    return output


def singleton(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and value in {0, 1}:
        return value
    return None


def lifecycle_singleton(event: dict[str, Any], name: str) -> int | None:
    """Return an explicit once-only lifecycle value without inventing EOS."""

    return singleton(event.get(name))


def connection_record(event: dict[str, Any]) -> dict[str, object] | None:
    identity = transport_identity(event)
    if identity is None:
        return None
    # Start/finish/destroy and body-finalization are lifecycle facts that a
    # future host driver must actually publish.  A transaction ID or a Phase-4
    # callback alone is not enough to manufacture them.
    required = {
        name: lifecycle_singleton(event, name)
        for name in (
            "transaction_started", "transaction_finished", "transaction_destroyed",
            "request_body_finished", "response_body_finished", "eos_seen",
        )
    }
    if any(value is None for value in required.values()):
        return None
    client_disconnect = lifecycle_singleton(event, "client_disconnect")
    upstream_disconnect = lifecycle_singleton(event, "upstream_disconnect")
    stream_reset = lifecycle_singleton(event, "stream_reset")
    timeout = lifecycle_singleton(event, "timeout")
    intentional_abort = lifecycle_singleton(event, "intentional_abort")
    if client_disconnect is None:
        client_disconnect = int(event.get("client_disconnected") is True)
    if upstream_disconnect is None:
        upstream_disconnect = int(event.get("upstream_disconnected") is True)
    if stream_reset is None:
        stream_reset = int(
            event.get("stream_reset") is True
            or canonical_transport_result(event) == "stream_reset"
        )
    if timeout is None:
        timeout = int(
            normalized_enum(event.get("timeout_stage"), TIMEOUT_STAGES) is not None
            or canonical_transport_result(event) == "timeout"
        )
    if intentional_abort is None:
        # Intentionality is security-sensitive.  Do not turn an internal host
        # failure into a strict abort merely because it happened near a deny.
        intentional_abort = 0
    short_writes = event.get("short_writes")
    if not isinstance(short_writes, int) or isinstance(short_writes, bool) or short_writes < 0:
        short_writes = int(normalized_enum(event.get("write_result"), WRITE_RESULTS) == "short_write")
    write_would_block = event.get("write_would_block")
    if not isinstance(write_would_block, int) or isinstance(write_would_block, bool) or write_would_block < 0:
        write_would_block = int(normalized_enum(event.get("write_result"), WRITE_RESULTS) == "write_would_block")
    return {
        "transaction_id": identity["transaction_id"],
        "transport_case_id": identity["transport_case_id"],
        "protocol": identity["protocol"],
        "connection_id": safe_connection_id(identity["protocol"], event.get("connection_id")),
        "stream_id": optional_stream_id(event.get("stream_id")),
        "connection_reused": event.get("connection_reused") if isinstance(event.get("connection_reused"), bool) else None,
        **required,
        "intentional_abort": intentional_abort,
        "client_disconnect": client_disconnect,
        "upstream_disconnect": upstream_disconnect,
        "stream_reset": stream_reset,
        "timeout": timeout,
        "short_writes": short_writes,
        "write_would_block": write_would_block,
        "cleanup_reason": normalized_enum(event.get("cleanup_reason"), CLEANUP_REASONS),
    }


def barrier_record(
    event: dict[str, Any], connector: str, integration_mode: str, run_id: str,
) -> dict[str, object] | None:
    identity = transport_identity(event)
    if identity is None:
        return None
    if identity["rule_id"] is None:
        return None
    if not (
        event.get("response_committed") is True
        and event.get("client_first_byte_received") is True
        and event.get("first_byte_before_response_end") is True
        and event.get("upstream_paused") is True
        and event.get("upstream_eos_sent_at_first_byte") is False
    ):
        return None
    requested_action = normalized_enum(event.get("requested_action"), REQUESTED_ACTIONS)
    actual_action = normalized_enum(event.get("actual_action"), ACTUAL_ACTIONS)
    transport_result = canonical_transport_result(event)
    if requested_action is None or actual_action is None or transport_result is None:
        return None
    # Framework finalization treats barrier-events.jsonl as canonical event
    # JSONL, not as a second observation schema.  Keep it event-shaped: it has
    # run identity and transport_case_id, but never a catalog-only case_id or
    # a sidecar-only ``protocol`` key.
    output: dict[str, object] = {
        "connector": connector,
        "integration_mode": integration_mode,
        "run_id": run_id,
        "transaction_id": identity["transaction_id"],
        "transport_case_id": identity["transport_case_id"],
        "rule_id": identity["rule_id"],
        "phase": identity["phase"],
        "event": identity["event"],
        "message_id": identity["message_id"],
        "requested_action": requested_action,
        "actual_action": actual_action,
        "transport_result": transport_result,
        "negotiated_protocol": identity["protocol"],
        "connection_id": safe_connection_id(identity["protocol"], event.get("connection_id")),
        "stream_id": optional_stream_id(event.get("stream_id")),
        "connection_reused": event.get("connection_reused") if isinstance(event.get("connection_reused"), bool) else None,
        "barrier_id": bounded_token(event.get("barrier_id")),
        "response_committed": event.get("response_committed") is True,
        "client_first_byte_received": event.get("client_first_byte_received") is True,
        "first_byte_before_response_end": event.get("first_byte_before_response_end") is True,
        "upstream_paused": event.get("upstream_paused") is True,
        "upstream_eos_sent_at_first_byte": event.get("upstream_eos_sent_at_first_byte") is True,
        "upstream_response_finished_at_first_byte": event.get("upstream_response_finished_at_first_byte") is True,
        "eos_seen": event.get("eos_seen") is True,
    }
    for name in ("first_chunk_size", "body_bytes_seen", "body_bytes_inspected"):
        value = event.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            output[name] = value
    return {name: value for name, value in output.items() if value is not None}


def build_artifacts(connector: str, run_id: str, events: list[dict[str, Any]]) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]], dict[str, int]]:
    integration_mode = CONNECTOR_INTEGRATION_MODES[connector]
    observations = [record for event in events if (record := observation_from_event(event)) is not None]
    transactions: dict[tuple[str, str], dict[str, object]] = {}
    for event in events:
        record = connection_record(event)
        if record is not None:
            transactions[(str(record["transaction_id"]), str(record["transport_case_id"]))] = record
    barriers = [
        record for event in events
        if (record := barrier_record(event, connector, integration_mode, run_id)) is not None
    ]
    counters = {
        "events": len(events),
        "transactions": len(transactions),
        "client_disconnects": sum(1 for event in events if event.get("client_disconnected") is True),
        "upstream_disconnects": sum(1 for event in events if event.get("upstream_disconnected") is True),
        "stream_resets": sum(1 for event in events if event.get("stream_reset") is True),
        "timeouts": sum(1 for event in events if bounded_token(event.get("timeout_stage")) is not None),
        "short_writes": sum(1 for event in events if event.get("write_result") == "short_write"),
        "write_would_block": sum(1 for event in events if event.get("write_result") == "write_would_block"),
    }
    observations_document: dict[str, object] = {
        "schema_version": 1,
        "connector": connector,
        "integration_mode": integration_mode,
        "run_id": run_id,
        "observations": observations,
    }
    lifecycle_document: dict[str, object] = {
        "schema_version": 1,
        "connector": connector,
        "integration_mode": integration_mode,
        "run_id": run_id,
        "records": list(transactions.values()),
    }
    return observations_document, lifecycle_document, barriers, counters


def write_logs(runtime_root: Path, output_dir: Path, connector: str, counters: dict[str, int]) -> None:
    common = [
        f"connector={connector}",
        "artifact_scope=payload_free_inventory_only",
        f"events={counters['events']}",
        f"transactions={counters['transactions']}",
    ]
    write_runtime_artifact_text_atomic(
        runtime_root,
        output_dir / "client.log",
        "\n".join([*common, "client_result=not_observed"]) + "\n",
        "transport client log",
    )
    write_runtime_artifact_text_atomic(
        runtime_root,
        output_dir / "upstream.log",
        "\n".join([*common, f"upstream_disconnects={counters['upstream_disconnects']}"]) + "\n",
        "transport upstream log",
    )
    write_runtime_artifact_text_atomic(
        runtime_root,
        output_dir / "transport.log",
        "\n".join(
            [
                *common,
                f"client_disconnects={counters['client_disconnects']}",
                f"stream_resets={counters['stream_resets']}",
                f"timeouts={counters['timeouts']}",
                f"short_writes={counters['short_writes']}",
                f"write_would_block={counters['write_would_block']}",
            ]
        ) + "\n",
        "transport summary log",
    )
    write_runtime_artifact_text_atomic(
        runtime_root,
        output_dir / "cleanup.log",
        "\n".join([*common, "process_cleanup=recorded_by_canonical_runner"]) + "\n",
        "transport cleanup log",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_source_root(value: Path, label: str) -> Path:
    """Validate an exact read-only source root selected for one invocation."""

    if not value.is_absolute():
        raise ValueError(f"{label} must be absolute: {value}")
    if ".." in value.parts:
        raise ValueError(f"{label} must not contain '..': {value}")
    lexical = Path(os.path.abspath(os.fspath(value)))
    resolved = lexical.resolve(strict=True)
    if lexical != resolved:
        raise ValueError(f"{label} must not use symbolic links: {lexical}")
    if not resolved.is_dir():
        raise ValueError(f"{label} must be an existing directory: {resolved}")
    return resolved


def source_file_under_root(value: Path, root: Path, label: str) -> Path:
    """Accept a regular non-symlink source file under one selected root."""

    if not value.is_absolute():
        raise ValueError(f"{label} must be absolute: {value}")
    if ".." in value.parts:
        raise ValueError(f"{label} must not contain '..': {value}")
    lexical = Path(os.path.abspath(os.fspath(value)))
    try:
        lexical.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must be below the selected source root: {lexical}") from exc
    resolved = lexical.resolve(strict=True)
    if lexical != resolved:
        raise ValueError(f"{label} must not use symbolic links: {lexical}")
    if not resolved.is_file():
        raise ValueError(f"{label} must be an existing regular file: {resolved}")
    return resolved


def is_lexically_under(value: Path, root: Path) -> bool:
    try:
        value.relative_to(root)
    except ValueError:
        return False
    return True


def parse_config_file(
    value: str,
    config_source_root: Path,
    framework_root: Path | None = None,
) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("config file must be LABEL=PATH")
    label, raw_path = value.split("=", 1)
    if not label or not all(character.isascii() and (character.isalnum() or character in "._/-") for character in label):
        raise ValueError(f"unsafe effective config label: {label!r}")
    candidate = Path(raw_path)
    if framework_root is not None and candidate.is_absolute():
        lexical = Path(os.path.abspath(os.fspath(candidate)))
        if is_lexically_under(lexical, framework_root):
            path = source_file_under_root(
                candidate, framework_root, "effective config source"
            )
            return label, path
    path = runtime_or_source_artifact_path(
        config_source_root, candidate, "effective config source", must_exist=True
    )
    return label, path


def write_effective_config(
    output_dir: Path,
    connector: str,
    run_id: str,
    values: Iterable[str],
    runtime_root: Path,
    config_source_root: Path | None = None,
    framework_root: Path | None = None,
) -> None:
    output_dir = runtime_artifact_path(
        runtime_root,
        output_dir,
        "effective configuration output directory",
    )
    output_dir = ensure_safe_runtime_directory(output_dir)
    config_source_root = config_source_root or runtime_root
    files = []
    for value in values:
        label, path = parse_config_file(value, config_source_root, framework_root)
        files.append({"path": label, "sha256": sha256_file(path)})
    files.sort(key=lambda item: str(item["path"]))
    write_json(runtime_root, output_dir / "manifest.json", {
        "schema_version": 1,
        "connector": connector,
        "integration_mode": CONNECTOR_INTEGRATION_MODES[connector],
        "run_id": run_id,
        "files": files,
    }, "effective configuration manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True, choices=tuple(CONNECTOR_INTEGRATION_MODES))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--effective-config-dir", type=Path)
    parser.add_argument("--config-file", action="append", default=[])
    parser.add_argument("--config-source-root", type=Path)
    parser.add_argument("--framework-root", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    args = parser.parse_args(argv)
    runtime_root = prepare_verified_runtime_artifact_root(args.runtime_root)
    run_id = bounded_token(args.run_id, maximum=256)
    if run_id is None:
        raise ValueError("run id must be a bounded metadata token")
    if (args.events is None) != (args.output_dir is None):
        raise ValueError("events and output directory must be supplied together")
    if args.events is None and args.effective_config_dir is None:
        raise ValueError("transport output or effective config output is required")
    if args.config_source_root is not None and args.effective_config_dir is None:
        raise ValueError("config source root requires effective config output")
    if args.framework_root is not None and args.effective_config_dir is None:
        raise ValueError("framework root requires effective config output")
    if args.events is not None and args.output_dir is not None:
        events_path = runtime_artifact_path(
            runtime_root, args.events, "events", must_exist=True
        )
        output_dir = runtime_artifact_path(
            runtime_root, args.output_dir, "output directory"
        )
        output_dir = ensure_safe_runtime_directory(output_dir)
        events = load_events(events_path)
        observations, lifecycle, barriers, counters = build_artifacts(args.connector, run_id, events)
        write_json(
            runtime_root,
            output_dir / "transport-observations.json",
            observations,
            "transport observations",
        )
        write_json(
            runtime_root,
            output_dir / "connection-lifecycle.json",
            lifecycle,
            "transport lifecycle",
        )
        write_jsonl(
            runtime_root,
            output_dir / "barrier-events.jsonl",
            barriers,
            "transport barrier events",
        )
        write_logs(runtime_root, output_dir, args.connector, counters)
    if args.effective_config_dir is not None:
        effective_config_dir = runtime_artifact_path(
            runtime_root, args.effective_config_dir, "effective config directory"
        )
        config_source_root = runtime_root
        if args.config_source_root is not None:
            config_source_root = prepare_verified_runtime_artifact_root(
                args.config_source_root
            )
        framework_root = None
        if args.framework_root is not None:
            framework_root = canonical_source_root(args.framework_root, "framework root")
        write_effective_config(
            effective_config_dir,
            args.connector,
            run_id,
            args.config_file,
            runtime_root,
            config_source_root,
            framework_root,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"transport-lifecycle-artifacts: {exc}")
        raise SystemExit(1)
