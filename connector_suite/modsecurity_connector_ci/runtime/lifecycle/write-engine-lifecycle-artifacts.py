#!/usr/bin/env python3
"""Write payload-free engine provenance and lifecycle inventory sidecars.

The sidecars describe only transaction identifiers and aggregate counters from
the current raw host run.  They deliberately do not participate in capability
selection or PASS promotion; canonical event validation remains the sole
promotion gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Iterable




from modsecurity_connector_ci.lib.runtime_path_utils import is_under, prepare_verified_runtime_artifact_root, runtime_artifact_path, runtime_or_source_artifact_path


FORBIDDEN_EVENT_KEYS = {
    "authorization",
    "body",
    "body_content",
    "body_payload",
    "body_snippet",
    "cookie",
    "matched_value",
    "matched_value_snippet",
    "password",
    "payload",
    "request_body",
    "response_body",
    "rule_message",
    "secret",
    "snippet",
}


def sha256_file(path: Path) -> str:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe lifecycle hashing requires O_NOFOLLOW")
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | no_follow)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"hash input must be a regular file: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def canonical_framework_root(value: Path) -> Path:
    """Validate the exact read-only Framework root selected for this run."""

    if not value.is_absolute():
        raise ValueError(f"framework root must be absolute: {value}")
    if ".." in value.parts:
        raise ValueError(f"framework root must not contain '..': {value}")
    lexical = Path(os.path.abspath(os.fspath(value)))
    resolved = lexical.resolve(strict=True)
    if lexical != resolved:
        raise ValueError(f"framework root must not use symbolic links: {lexical}")
    if not resolved.is_dir():
        raise ValueError(f"framework root must be an existing directory: {resolved}")
    return resolved


def framework_rules_path(value: Path | str, framework_root: Path | None) -> Path | None:
    """Return one regular no-symlink rules file below the selected Framework."""

    if framework_root is None:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"rules must be absolute: {candidate}")
    if ".." in candidate.parts:
        raise ValueError(f"rules must not contain '..': {candidate}")
    lexical = Path(os.path.abspath(os.fspath(candidate)))
    try:
        lexical.relative_to(framework_root)
    except ValueError:
        return None
    resolved = lexical.resolve(strict=True)
    if lexical != resolved:
        raise ValueError(f"rules must not use symbolic links: {lexical}")
    if not resolved.is_file():
        raise ValueError(f"rules must be an existing regular file: {resolved}")
    return resolved


def managed_library_path(library_value: Path | str, root_value: Path | str) -> Path:
    """Resolve the managed SONAME without widening the provenance read scope.

    The lifecycle runner provides the immutable libmodsecurity cache directory
    it obtained from the target-bound runtime-component snapshot.  A SONAME
    link is normal, but neither the input name nor its resolved target may
    leave that directory.
    """

    library_root = Path(root_value)
    if not library_root.is_absolute() or not library_root.is_dir() or library_root.is_symlink():
        raise ValueError(f"managed library root must be an absolute real directory: {library_root}")
    for candidate in library_root.parents:
        if candidate.is_symlink():
            raise ValueError(f"managed library root contains a symlink: {candidate}")
    library = Path(library_value)
    if not library.is_absolute() or not is_under(library, library_root):
        raise ValueError(f"library must be below the managed library root: {library}")
    try:
        resolved = library.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"cannot resolve managed library: {library}: {exc}") from exc
    if not resolved.is_file() or not is_under(resolved, library_root):
        raise ValueError(f"library must resolve to a regular managed file: {library}")
    return resolved


def ensure_safe_directory(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("output directory must be absolute")
    for candidate in (path, *path.parents):
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"output directory contains a symlink: {candidate}")
        if candidate == candidate.parent:
            break
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"output directory is not a real directory: {path}")


def atomic_write(path: Path, payload: bytes) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing to replace symlink artifact: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load source result {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"source result must be an object: {path}")
    return value


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot load source events {path}: {exc}") from exc
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"source events line {number} is not JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"source events line {number} must be an object")
        forbidden = sorted(FORBIDDEN_EVENT_KEYS.intersection(value))
        if forbidden:
            raise ValueError(
                f"source events line {number} contains forbidden payload metadata: "
                + ", ".join(forbidden)
            )
        events.append(value)
    return events


def contains_forbidden_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in FORBIDDEN_EVENT_KEYS or contains_forbidden_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_forbidden_key(item) for item in value)
    return False


def load_transport_lifecycle(path: Path, connector: str) -> list[dict[str, Any]]:
    """Read the already-derived causal lifecycle inventory once.

    The engine counter writer runs after the transport writer.  Reusing that
    bounded inventory for transport counters avoids maintaining two subtly
    different interpretations of disconnect, reset, timeout, and cleanup.
    It does not make the inventory promotable: Framework still requires a
    matching canonical case result and event.
    """

    if not path.is_file() or path.is_symlink():
        raise ValueError(f"transport lifecycle must be a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load transport lifecycle {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("connector") != connector:
        raise ValueError("transport lifecycle has invalid connector identity")
    records = payload.get("records")
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError("transport lifecycle records must be an object list")
    if contains_forbidden_key(payload):
        raise ValueError("transport lifecycle contains forbidden payload metadata")
    return [dict(record) for record in records]


def transaction_ids(source: dict[str, Any], events: Iterable[dict[str, Any]]) -> list[str]:
    identifiers: set[str] = set()
    raw_ids = source.get("transaction_ids", [])
    if not isinstance(raw_ids, list):
        raise ValueError("source result transaction_ids must be a list")
    for value in raw_ids:
        identifier = str(value).strip()
        if identifier:
            identifiers.add(identifier)
    for event in events:
        identifier = str(event.get("transaction_id") or "").strip()
        if identifier:
            identifiers.add(identifier)
    return sorted(identifiers)


def phase_number(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    aliases = {
        "request_headers": 1,
        "request_body": 2,
        "response_headers": 3,
        "response_body": 4,
    }
    if text in aliases:
        return aliases[text]
    try:
        return int(text)
    except ValueError:
        return None


def unique_event_signature(event: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return tuple(
        str(event.get(name) or "")
        for name in (
            "transaction_id",
            "phase",
            "rule_id",
            "requested_action",
            "actual_action",
            "status",
        )
    )


def engine_error_event(event: dict[str, Any]) -> bool:
    values = " ".join(
        str(event.get(name) or "").lower()
        for name in ("event", "message_id", "status", "actual_action", "transport_result")
    )
    return "engine_error" in values or "adapter_error" in values or "host_filter_error" in values


def canonical_transport_token(value: object) -> str:
    """Return a comparison-only transport token without retaining payload data."""

    return str(value or "").strip().lower().replace("-", "_")


def event_flag(event: dict[str, Any], name: str) -> bool:
    """Only an explicit JSON true counts as a lifecycle observation."""

    return event.get(name) is True


def event_transaction_ids(events: Iterable[dict[str, Any]], predicate: Any) -> set[str]:
    return {
        str(event.get("transaction_id"))
        for event in events
        if event.get("transaction_id") and predicate(event)
    }


def bounded_record_counter(record: dict[str, Any], name: str) -> int:
    value = record.get(name, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def record_counter(records: Iterable[dict[str, Any]], name: str) -> int:
    return sum(bounded_record_counter(record, name) for record in records)


def build_artifacts(
    *,
    connector: str,
    source: dict[str, Any],
    events: list[dict[str, Any]],
    libmodsecurity_version: str,
    library_sha256: str,
    ruleset_sha256: str,
    stage_exit_code: int,
    transport_lifecycle_records: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    identifiers = transaction_ids(source, events)
    unique_events = {unique_event_signature(event) for event in events}
    phase2_transactions = {
        str(event.get("transaction_id"))
        for event in events
        if event.get("transaction_id") and phase_number(event.get("phase")) == 2
    }
    phase4_transactions = {
        str(event.get("transaction_id"))
        for event in events
        if event.get("transaction_id") and phase_number(event.get("phase")) == 4
    }
    abort_transactions = {
        str(event.get("transaction_id"))
        for event in events
        if event.get("transaction_id")
        and (
            str(event.get("actual_action") or "") in {"abort_connection", "stream_reset"}
            or event_flag(event, "intentional_abort")
        )
    }
    error_signatures = {
        unique_event_signature(event) for event in events if engine_error_event(event)
    }
    client_disconnect_transactions = event_transaction_ids(
        events,
        lambda event: event_flag(event, "client_disconnected")
        or canonical_transport_token(event.get("transport_result"))
        in {"client_cancelled", "client_disconnected"},
    )
    upstream_disconnect_transactions = event_transaction_ids(
        events,
        lambda event: event_flag(event, "upstream_disconnected")
        or canonical_transport_token(event.get("transport_result"))
        in {"upstream_reset", "upstream_disconnected"},
    )
    stream_reset_transactions = event_transaction_ids(
        events,
        lambda event: event_flag(event, "stream_reset")
        or canonical_transport_token(event.get("transport_result")) == "stream_reset",
    )
    timeout_transactions = event_transaction_ids(
        events,
        lambda event: bool(canonical_transport_token(event.get("timeout_stage")))
        or canonical_transport_token(event.get("transport_result")) == "timeout",
    )
    short_write_transactions = event_transaction_ids(
        events,
        lambda event: canonical_transport_token(event.get("write_result")) == "short_write"
        or canonical_transport_token(event.get("transport_result")) == "short_write",
    )
    would_block_transactions = event_transaction_ids(
        events,
        lambda event: canonical_transport_token(event.get("write_result")) == "write_would_block"
        or canonical_transport_token(event.get("transport_result")) == "write_would_block",
    )
    cleanup_normal_transactions = event_transaction_ids(
        events,
        lambda event: canonical_transport_token(event.get("cleanup_reason")) == "normal",
    )
    cleanup_cancel_transactions = event_transaction_ids(
        events,
        lambda event: canonical_transport_token(event.get("cleanup_reason"))
        in {"cancelled", "client_disconnected", "upstream_disconnected"},
    )
    cleanup_abort_transactions = event_transaction_ids(
        events,
        lambda event: canonical_transport_token(event.get("cleanup_reason"))
        in {"strict_abort", "stream_reset"},
    )
    bound_records = list(transport_lifecycle_records or [])
    transport_counters_bound = bool(bound_records)
    if transport_counters_bound:
        client_disconnect_count = record_counter(bound_records, "client_disconnect")
        upstream_disconnect_count = record_counter(bound_records, "upstream_disconnect")
        stream_reset_count = record_counter(bound_records, "stream_reset")
        timeout_count = record_counter(bound_records, "timeout")
        short_write_count = record_counter(bound_records, "short_writes")
        would_block_count = record_counter(bound_records, "write_would_block")
        cleanup_normal_count = sum(record.get("cleanup_reason") == "normal" for record in bound_records)
        cleanup_cancel_count = sum(
            record.get("cleanup_reason") in {"cancelled", "client_disconnected", "upstream_disconnected"}
            for record in bound_records
        )
        cleanup_abort_count = sum(
            record.get("cleanup_reason") in {"strict_abort", "stream_reset"}
            for record in bound_records
        )
        # A bound transport inventory is the causal source of the transport
        # counters.  Do not let a separate, unbound diagnostic event inflate a
        # strict-abort total that Framework must reconcile exactly to the
        # lifecycle records.
        intentional_abort_count = record_counter(bound_records, "intentional_abort")
    else:
        client_disconnect_count = len(client_disconnect_transactions)
        upstream_disconnect_count = len(upstream_disconnect_transactions)
        stream_reset_count = len(stream_reset_transactions)
        timeout_count = len(timeout_transactions)
        short_write_count = len(short_write_transactions)
        would_block_count = len(would_block_transactions)
        cleanup_normal_count = len(cleanup_normal_transactions)
        cleanup_cancel_count = len(cleanup_cancel_transactions)
        cleanup_abort_count = len(cleanup_abort_transactions)
        intentional_abort_count = len(abort_transactions)
    accounting_scope = "unique transaction IDs in the current raw host result and normalized engine events"
    counts = {
        "schema_version": 1,
        "connector": connector,
        "accounting_scope": accounting_scope,
        "transaction_ids": identifiers,
        "transactions_observed": len(identifiers),
        "unique_engine_events_observed": len(unique_events),
        "stage_exit_code": stage_exit_code,
    }
    lifecycle = {
        "schema_version": 1,
        "connector": connector,
        "accounting_scope": accounting_scope,
        "counter_basis": (
            "A successful host stage and each unique transaction ID in the current "
            "raw result/event stream; sidecar counters are non-promoting inventory."
        ),
        "transactions_started": len(identifiers),
        "transactions_finished": len(identifiers),
        "transactions_destroyed": len(identifiers),
        "request_body_finishes": max(
            len(phase2_transactions), record_counter(bound_records, "request_body_finished"),
        ),
        "response_body_finishes": max(
            len(phase4_transactions), record_counter(bound_records, "response_body_finished"),
        ),
        "interventions_seen": len(unique_events),
        "intentional_aborts": intentional_abort_count,
        "client_disconnects": client_disconnect_count,
        "upstream_disconnects": upstream_disconnect_count,
        "stream_resets": stream_reset_count,
        "timeouts": timeout_count,
        "short_writes": short_write_count,
        "write_would_block": would_block_count,
        "cleanup_normal": cleanup_normal_count,
        "cleanup_cancel": cleanup_cancel_count,
        "cleanup_abort": cleanup_abort_count,
        "transport_counters_bound": transport_counters_bound,
        "unexpected_engine_errors": len(error_signatures),
        "stage_exit_code": stage_exit_code,
        "engine_version": libmodsecurity_version,
        "engine_library_sha256": library_sha256,
        "ruleset_sha256": ruleset_sha256,
    }
    return counts, lifecycle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--source-result", required=True)
    parser.add_argument("--source-events", required=True)
    parser.add_argument("--rules-file", required=True)
    parser.add_argument("--libmodsecurity-version", required=True)
    parser.add_argument("--libmodsecurity-library", required=True)
    parser.add_argument("--libmodsecurity-library-root", required=True)
    parser.add_argument("--stage-exit-code", required=True, type=int)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--transport-lifecycle", type=Path)
    parser.add_argument("--framework-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.stage_exit_code != 0:
        raise ValueError("engine lifecycle sidecars require a successful host stage")
    runtime_root = prepare_verified_runtime_artifact_root(args.runtime_root)
    source_path = runtime_artifact_path(
        runtime_root, args.source_result, "source result", must_exist=True
    )
    events_path = runtime_artifact_path(
        runtime_root, args.source_events, "source events", must_exist=True
    )
    framework_root = (
        canonical_framework_root(args.framework_root)
        if args.framework_root is not None
        else None
    )
    rules_path = framework_rules_path(args.rules_file, framework_root)
    if rules_path is None:
        rules_path = runtime_or_source_artifact_path(
            runtime_root, args.rules_file, "rules", must_exist=True
        )
    library_path = managed_library_path(
        args.libmodsecurity_library,
        args.libmodsecurity_library_root,
    )
    for label, path in (("source result", source_path), ("source events", events_path), ("rules", rules_path)):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{label} must be a regular file: {path}")
    version = str(args.libmodsecurity_version).strip()
    if not version or version == "not_provisioned":
        raise ValueError("libmodsecurity version must be concrete")
    output_dir = runtime_artifact_path(runtime_root, args.output_dir, "output directory")
    ensure_safe_directory(output_dir)
    source = load_json(source_path)
    events = load_events(events_path)
    transport_lifecycle_records = []
    if args.transport_lifecycle is not None:
        transport_lifecycle = runtime_artifact_path(
            runtime_root,
            args.transport_lifecycle,
            "transport lifecycle",
            must_exist=True,
        )
        transport_lifecycle_records = load_transport_lifecycle(
            transport_lifecycle, args.connector
        )
    library_sha256 = sha256_file(library_path)
    ruleset_sha256 = sha256_file(rules_path)
    counts, lifecycle = build_artifacts(
        connector=args.connector,
        source=source,
        events=events,
        libmodsecurity_version=version,
        library_sha256=library_sha256,
        ruleset_sha256=ruleset_sha256,
        stage_exit_code=args.stage_exit_code,
        transport_lifecycle_records=transport_lifecycle_records,
    )
    atomic_write(output_dir / "engine-version.txt", f"{version}\n".encode("utf-8"))
    atomic_write(output_dir / "engine-library-sha256.txt", f"{library_sha256}\n".encode("ascii"))
    atomic_write(output_dir / "ruleset-sha256.txt", f"{ruleset_sha256}\n".encode("ascii"))
    atomic_write(
        output_dir / "transaction-counts.json",
        (json.dumps(counts, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    atomic_write(
        output_dir / "lifecycle-counters.json",
        (json.dumps(lifecycle, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"engine-lifecycle-artifacts: {exc}", file=sys.stderr)
        raise SystemExit(1)
