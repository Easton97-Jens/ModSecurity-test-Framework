#!/usr/bin/env python3
"""Check the compact real-host HTTP/1.1 lifecycle profile for all connectors.

This is deliberately a read-only acceptance gate.  It consumes canonical
full-lifecycle artifacts produced by the existing runner; it does not infer
capabilities, edit manifests, normalize events, or promote anything.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
IDENTITIES = {
    "apache": ("native-httpd-module", "native-httpd-module", "full-lifecycle-apache"),
    "nginx": ("native-nginx-http-module", "native-nginx-http-module", "full-lifecycle-nginx"),
    "haproxy": ("native-htx-filter", "native-htx-filter", "full-lifecycle-haproxy-htx"),
    "envoy": ("ext_proc", "ext_proc", "full-lifecycle-envoy-ext-proc"),
    "traefik": ("native-middleware", "native-traefik-middleware", "full-lifecycle-traefik-native"),
    "lighttpd": ("patched-native", "patched-native-lighttpd", "full-lifecycle-lighttpd-patched"),
}
CORE_CASES = {
    "allow_without_marker": (1, None),
    "deny_header_marker_403": (1, 1100001),
    "deny_request_body_marker_403": (2, 1100101),
    "deny_response_header_marker_403": (3, 1100201),
    "phase4_rule_observed": (4, 1100301),
    "phase4_deny_after_commit_log_only_safe": (4, 1100301),
    "phase4_first_byte_before_response_end": (4, 1100301),
    "phase4_no_full_response_buffering": (4, 1100301),
}
ALTERNATIVE_CASES = {
    "deny_with_alternative_status": (1, 1100002),
    "phase3_redirect_before_commit": (3, 1100202),
}
REQUIRED_ARTIFACTS = (
    "manifest.json",
    "result.json",
    "results.jsonl",
    "events.jsonl",
    "inventory/run.json",
    "logs/stdout.log",
    "logs/stderr.log",
    "logs/host.log",
    "logs/client.log",
    "logs/upstream.log",
    "logs/cleanup.log",
    "engine-version.txt",
    "engine-library-sha256.txt",
    "ruleset-sha256.txt",
    "transaction-counts.json",
    "lifecycle-counters.json",
    "inventory/first-byte-evidence.json",
    "effective-config/manifest.json",
)
FORBIDDEN_KEYS = {
    "authorization",
    "body",
    "body_content",
    "body_payload",
    "body_snippet",
    "cookie",
    "cookies",
    "matched_value",
    "matched_value_snippet",
    "password",
    "payload",
    "request_body",
    "response_body",
    "rule_message",
    "secret",
}
BODY_SENTINELS = ("no-crs-request-body-marker", "no-crs-response-body-marker")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON object required")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: JSON object required")
        records.append(value)
    return records


def normalized_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def contains_forbidden(value: object) -> bool:
    if isinstance(value, dict):
        return any(str(key).lower() in FORBIDDEN_KEYS or contains_forbidden(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(contains_forbidden(item) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return any(sentinel in lowered for sentinel in BODY_SENTINELS)
    return False


def event_matches(
    events: Iterable[dict[str, Any]], *, connector: str, integration_mode: str,
    phase: int, rule_id: int, transaction_ids: set[str],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for event in events:
        if event.get("connector") != connector or event.get("integration_mode") != integration_mode:
            continue
        if normalized_int(event.get("phase")) != phase or normalized_int(event.get("rule_id")) != rule_id:
            continue
        if str(event.get("transaction_id") or "") not in transaction_ids:
            continue
        matches.append(event)
    return matches


def require_case(
    *, connector: str, records: dict[str, dict[str, Any]], case_id: str,
    phase: int, rule_id: int | None, integration_mode: str, events: list[dict[str, Any]],
    errors: list[str],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    record = records.get(case_id)
    if record is None:
        errors.append(f"{connector}: missing core case {case_id}")
        return None, []
    if record.get("status") != "PASS":
        errors.append(f"{connector}: {case_id} is {record.get('status')}, expected PASS")
        return record, []
    if record.get("integration_mode") != integration_mode:
        errors.append(f"{connector}: {case_id} integration mode is not the selected real host")
    if normalized_int(record.get("phase")) != phase:
        errors.append(f"{connector}: {case_id} phase does not match {phase}")
    if rule_id is None:
        return record, []
    if normalized_int(record.get("expected_rule_id")) != rule_id:
        errors.append(f"{connector}: {case_id} does not declare canonical rule {rule_id}")
    transaction_ids = {
        str(value) for value in record.get("transaction_ids", [])
        if isinstance(value, (str, int)) and str(value)
    }
    if not transaction_ids:
        errors.append(f"{connector}: {case_id} has no causally bound transaction ID")
        return record, []
    matches = event_matches(
        events, connector=connector, integration_mode=integration_mode,
        phase=phase, rule_id=rule_id, transaction_ids=transaction_ids,
    )
    if not matches:
        errors.append(f"{connector}: {case_id} has no same-transaction raw host event")
    return record, matches


def safe_event(event: dict[str, Any]) -> bool:
    return (
        event.get("requested_action") == "deny"
        and event.get("actual_action") == "log_only"
        and event.get("late_intervention") is True
        and event.get("late_intervention_mode") == "safe"
        and event.get("headers_sent") is True
        and event.get("body_started") is True
        and event.get("response_committed") is True
        and event.get("connection_aborted") is False
        and normalized_int(event.get("http_status")) == 403
        and normalized_int(event.get("original_http_status")) == 200
        and normalized_int(event.get("visible_http_status")) == 200
        and event.get("transport_result") == "log_only"
    )


def barrier_event(event: dict[str, Any], *, require_no_buffer: bool) -> bool:
    if not (
        event.get("client_first_byte_received") is True
        and event.get("first_byte_before_response_end") is True
        and event.get("upstream_paused") is True
        and event.get("upstream_eos_sent_at_first_byte") is False
        and event.get("upstream_response_finished_at_first_byte") is False
        and event.get("response_committed") is True
        and isinstance(event.get("first_chunk_size"), int)
        and not isinstance(event.get("first_chunk_size"), bool)
        and event["first_chunk_size"] > 0
    ):
        return False
    if require_no_buffer and event.get("no_full_response_buffering") is not True:
        return False
    return True


def required_artifact_errors(run_dir: Path, connector: str) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_ARTIFACTS:
        artifact = run_dir / relative
        if not artifact.is_file() or artifact.is_symlink():
            errors.append(f"{connector}: missing required artifact {relative}")
    return errors


def load_core_artifacts(
    run_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    return (
        load_json(run_dir / "result.json"),
        load_jsonl(run_dir / "events.jsonl"),
        load_jsonl(run_dir / "results.jsonl"),
        load_json(run_dir / "inventory/first-byte-evidence.json"),
        load_json(run_dir / "lifecycle-counters.json"),
    )


def result_contract_errors(
    connector: str, result: dict[str, Any], first_byte: dict[str, Any], host_profile: str, integration_mode: str, target: str,
) -> list[str]:
    errors: list[str] = []
    for field, expected, label in (
        ("artifact_profile", "full_lifecycle", "artifact profile"),
        ("host_profile", host_profile, "host profile"),
        ("integration_mode", integration_mode, "result integration mode"),
        ("executed_targets", [target], "executed target"),
    ):
        if result.get(field) != expected:
            errors.append(f"{connector}: {label} is not {expected}")
    if result.get("exit_code") != 0 or result.get("started") is not True:
        errors.append(f"{connector}: selected host did not complete successfully")
    if not isinstance(result.get("transaction_ids"), list) or not result["transaction_ids"]:
        errors.append(f"{connector}: result has no transaction-ID evidence")
    if first_byte.get("evidence_origin") != "real_host" or first_byte.get("promotion_eligible") is not True:
        errors.append(f"{connector}: first-byte proof is synthetic or not promotion-eligible")
    if first_byte.get("outcome") != "PASS" or first_byte.get("body_payload_persisted") is not False:
        errors.append(f"{connector}: first-byte evidence is not a payload-free PASS")
    return errors


def canonical_records(rows: list[dict[str, Any]], connector: str, errors: list[str]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for row in rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str):
            continue
        if case_id in records:
            errors.append(f"{connector}: duplicate canonical result for {case_id}")
        records[case_id] = row
    return records


def required_case_matches(
    connector: str, records: dict[str, dict[str, Any]], integration_mode: str, events: list[dict[str, Any]], errors: list[str],
) -> dict[str, list[dict[str, Any]]]:
    return {
        case_id: require_case(
            connector=connector, records=records, case_id=case_id, phase=phase,
            rule_id=rule_id, integration_mode=integration_mode, events=events, errors=errors,
        )[1]
        for case_id, (phase, rule_id) in CORE_CASES.items()
    }


def alternative_case_errors(
    connector: str, records: dict[str, dict[str, Any]], integration_mode: str, events: list[dict[str, Any]], errors: list[str],
) -> None:
    for case_id, (phase, rule_id) in ALTERNATIVE_CASES.items():
        record = records.get(case_id)
        if record is None or record.get("status") != "PASS":
            continue
        if require_case(
            connector=connector, records=records, case_id=case_id, phase=phase,
            rule_id=rule_id, integration_mode=integration_mode, events=events, errors=errors,
        )[1]:
            return
    errors.append(f"{connector}: neither alternative-status nor pre-commit redirect has real host evidence")


def client_status_errors(connector: str, records: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for case_id, expected_status in (
        ("allow_without_marker", 200),
        ("deny_header_marker_403", 403),
        ("deny_request_body_marker_403", 403),
        ("deny_response_header_marker_403", 403),
    ):
        record = records.get(case_id)
        if record is not None and record.get("status") == "PASS" and normalized_int(record.get("actual_status")) != expected_status:
            errors.append(f"{connector}: {case_id} client status is not {expected_status}")
    return errors


def phase4_evidence_errors(
    connector: str, matched: dict[str, list[dict[str, Any]]],
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    errors: list[str] = []
    safe_candidates = matched.get("phase4_deny_after_commit_log_only_safe", [])
    phase2_candidates = matched.get("deny_request_body_marker_403", [])
    if not any(safe_event(event) for event in safe_candidates):
        errors.append(f"{connector}: P4 Safe lacks requested/actual action and preserved HTTP/200 host evidence")
    if not any(event.get("eos_seen") is True for event in safe_candidates):
        errors.append(f"{connector}: P4 Safe lacks a real EOS evaluation event")
    if not any(barrier_event(event, require_no_buffer=False) for event in matched.get("phase4_first_byte_before_response_end", [])):
        errors.append(f"{connector}: first byte was not observed before upstream EOS")
    if not any(barrier_event(event, require_no_buffer=True) for event in matched.get("phase4_no_full_response_buffering", [])):
        errors.append(f"{connector}: no-full-response-buffer evidence is missing")
    return errors, safe_candidates, phase2_candidates


def transaction_ids(events: list[dict[str, Any]]) -> set[str]:
    return {str(event.get("transaction_id")) for event in events if str(event.get("transaction_id") or "")}


def safe_eos_errors(connector: str, events: list[dict[str, Any]], safe_transactions: set[str]) -> list[str]:
    errors: list[str] = []
    if not safe_transactions:
        errors.append(f"{connector}: P4 Safe has no transaction to audit for EOS")
    for transaction_id in safe_transactions:
        eos_events = [event for event in events if normalized_int(event.get("phase")) == 4 and str(event.get("transaction_id") or "") == transaction_id and event.get("eos_seen") is True]
        if len(eos_events) != 1:
            errors.append(f"{connector}: P4 Safe transaction {transaction_id} does not have exactly one EOS event")
    return errors


def phase2_eos_errors(
    connector: str, integration_mode: str, events: list[dict[str, Any]], lifecycle: dict[str, Any], phase2_transactions: set[str],
) -> list[str]:
    errors: list[str] = []
    all_phase2_transactions = {
        str(event.get("transaction_id")) for event in events
        if event.get("connector") == connector and event.get("integration_mode") == integration_mode
        and normalized_int(event.get("phase")) == 2 and str(event.get("transaction_id") or "")
    }
    if not phase2_transactions:
        errors.append(f"{connector}: P2 has no transaction to audit for EOS")
    if not phase2_transactions.issubset(all_phase2_transactions):
        errors.append(f"{connector}: P2 case transaction is absent from the raw Phase-2 event set")
    request_finishes = normalized_int(lifecycle.get("request_body_finishes"))
    if request_finishes is None or request_finishes != len(all_phase2_transactions):
        errors.append(f"{connector}: request-body EOS count is not exactly once per observed Phase-2 transaction")
    return errors


def lifecycle_balance_errors(connector: str, lifecycle: dict[str, Any], safe_transactions: set[str]) -> list[str]:
    errors: list[str] = []
    response_finishes = normalized_int(lifecycle.get("response_body_finishes"))
    if response_finishes is None or response_finishes < len(safe_transactions):
        errors.append(f"{connector}: lifecycle inventory lacks the P4 Safe response-body finish")
    counts = tuple(normalized_int(lifecycle.get(name)) for name in ("transactions_started", "transactions_finished", "transactions_destroyed"))
    if None in counts or counts[0] is None or counts[0] < 1 or not (counts[0] == counts[1] == counts[2]):
        errors.append(f"{connector}: transaction lifecycle cleanup is not balanced")
    if normalized_int(lifecycle.get("unexpected_engine_errors")) != 0:
        errors.append(f"{connector}: lifecycle inventory records unexpected engine errors")
    return errors


def lifecycle_eos_errors(
    connector: str, integration_mode: str, events: list[dict[str, Any]], lifecycle: dict[str, Any],
    safe_candidates: list[dict[str, Any]], phase2_candidates: list[dict[str, Any]],
) -> list[str]:
    safe_transactions = transaction_ids(safe_candidates)
    phase2_transactions = transaction_ids(phase2_candidates)
    errors = safe_eos_errors(connector, events, safe_transactions)
    errors.extend(phase2_eos_errors(connector, integration_mode, events, lifecycle, phase2_transactions))
    errors.extend(lifecycle_balance_errors(connector, lifecycle, safe_transactions))
    return errors


def check_connector(run_dir: Path, connector: str) -> list[str]:
    errors = required_artifact_errors(run_dir, connector)
    if errors:
        return errors
    try:
        result, events, rows, first_byte, lifecycle = load_core_artifacts(run_dir)
    except (OSError, ValueError) as exc:
        return [f"{connector}: cannot read canonical core artifacts: {exc}"]

    host_profile, integration_mode, target = IDENTITIES[connector]
    errors.extend(result_contract_errors(connector, result, first_byte, host_profile, integration_mode, target))
    if contains_forbidden(events):
        errors.append(f"{connector}: events contain body payload or sensitive metadata")
    records = canonical_records(rows, connector, errors)
    matched = required_case_matches(connector, records, integration_mode, events, errors)
    alternative_case_errors(connector, records, integration_mode, events, errors)
    errors.extend(client_status_errors(connector, records))
    phase_errors, safe_candidates, phase2_candidates = phase4_evidence_errors(connector, matched)
    errors.extend(phase_errors)
    errors.extend(lifecycle_eos_errors(connector, integration_mode, events, lifecycle, safe_candidates, phase2_candidates))
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    for connector in CONNECTORS:
        run_dir = args.evidence_root / connector / args.run_id
        if not run_dir.is_dir():
            errors.append(f"{connector}: canonical run directory is missing")
            continue
        errors.extend(check_connector(run_dir, connector))
    if errors:
        for error in errors:
            print(f"six-connector-core-completion: FAIL: {error}")
        return 1
    print("six-connector-core-completion: PASS (six real HTTP/1.1 P1-P4 core paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
