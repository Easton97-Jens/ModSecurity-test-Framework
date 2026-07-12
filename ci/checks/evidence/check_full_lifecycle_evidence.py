#!/usr/bin/env python3
"""Validate canonical full-lifecycle first-byte and promotion evidence.

This checker is intentionally separate from the legacy ``validate --check
all`` path: ordinary No-CRS smoke runs do not have a synchronized upstream
barrier.  The explicit Make targets call this program only for a selected
full-lifecycle run.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping


FRAMEWORK_ROOT = Path(__file__).resolve().parents[3]
RUNNER_ROOT = FRAMEWORK_ROOT / "tests" / "runners"
CATALOG_ROOT = FRAMEWORK_ROOT / "ci" / "checks" / "catalog"
for path in (CATALOG_ROOT, RUNNER_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import no_crs_baseline as no_crs  # noqa: E402
from synchronized_upstream import first_byte_evidence_errors  # noqa: E402


FULL_LIFECYCLE_CASES = {
    "phase4_first_byte_before_response_end",
    "phase4_no_full_response_buffering",
}
FIRST_BYTE_EVENT_FIELDS = (
    "client_first_byte_received",
    "first_byte_before_response_end",
    "first_chunk_size",
    "upstream_paused",
    "upstream_eos_sent_at_first_byte",
    "upstream_response_finished_at_first_byte",
    "response_committed",
    "body_bytes_seen",
    "body_bytes_inspected",
)
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


def _load_object(path: Path, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = no_crs.load_json(path)
    except Exception as exc:  # no_crs has a precise error but keep this CLI stable
        return None, [f"{label}: cannot read JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{label}: must be a JSON object"]
    return payload, []


def _canonical_base_errors(run_dir: Path, connector: str) -> list[str]:
    capabilities_path = run_dir / "inventory" / "capabilities.json"
    try:
        capabilities = no_crs.load_capability_manifest(capabilities_path, connector)
    except Exception as exc:
        return [f"inventory/capabilities.json: {exc}"]
    return no_crs.validate_run(run_dir, connector, capabilities, BASE_CHECKS)


def _first_byte_artifact(
    run_dir: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    result, result_errors = _load_object(run_dir / "result.json", "result.json")
    manifest, manifest_errors = _load_object(run_dir / "manifest.json", "manifest.json")
    errors = result_errors + manifest_errors
    if result is None or manifest is None:
        return result, manifest, None, errors
    if manifest.get("artifact_profile") != no_crs.FULL_LIFECYCLE_ARTIFACT_PROFILE:
        errors.append("canonical full-lifecycle checks require artifact_profile=full_lifecycle")
        return result, manifest, None, errors
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        errors.append("manifest artifacts must be an object")
        return result, manifest, None, errors
    entry = artifacts.get("first_byte_evidence")
    if not isinstance(entry, Mapping):
        errors.append("manifest is missing first_byte_evidence")
        return result, manifest, None, errors
    if entry.get("state") != "produced":
        errors.append("first_byte_evidence must be produced")
        return result, manifest, None, errors
    if entry.get("path") != no_crs.FIRST_BYTE_EVIDENCE_RELATIVE_PATH:
        errors.append(
            "first_byte_evidence must use " + no_crs.FIRST_BYTE_EVIDENCE_RELATIVE_PATH
        )
        return result, manifest, None, errors
    evidence, evidence_errors = _load_object(
        run_dir / no_crs.FIRST_BYTE_EVIDENCE_RELATIVE_PATH,
        no_crs.FIRST_BYTE_EVIDENCE_RELATIVE_PATH,
    )
    errors.extend(evidence_errors)
    return result, manifest, evidence, errors


def _case_records(run_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        return no_crs.read_jsonl(run_dir / "results.jsonl"), []
    except Exception as exc:
        return [], [f"results.jsonl: cannot read canonical records: {exc}"]


def _events(run_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        return no_crs.read_jsonl(run_dir / "events.jsonl"), []
    except Exception as exc:
        return [], [f"events.jsonl: cannot read canonical events: {exc}"]


def _passed_case(records: list[dict[str, Any]], case_id: str) -> bool:
    return any(
        record.get("case_id") == case_id
        and record.get("status") == "PASS"
        and record.get("live_executed") is True
        for record in records
    )


def _verified_capabilities(result: Mapping[str, Any]) -> set[str]:
    values = result.get("capabilities_verified", [])
    if not isinstance(values, list):
        return set()
    return {str(value) for value in values}


def _requires_first_byte_proof(
    result: Mapping[str, Any], records: list[dict[str, Any]],
) -> bool:
    return (
        _passed_case(records, "phase4_first_byte_before_response_end")
        or "first_byte_before_response_end" in _verified_capabilities(result)
    )


def _requires_no_buffer_proof(
    result: Mapping[str, Any], records: list[dict[str, Any]],
) -> bool:
    return (
        _passed_case(records, "phase4_no_full_response_buffering")
        or "no_full_response_buffering" in _verified_capabilities(result)
    )


def _matching_first_byte_event(
    events: list[dict[str, Any]], evidence: Mapping[str, Any]
) -> bool:
    for event in events:
        if no_crs.normalize_canonical_phase(event.get("phase")) != 4:
            continue
        if event.get("rule_id") not in {1100301, "1100301"}:
            continue
        if all(event.get(field) == evidence.get(field) for field in FIRST_BYTE_EVENT_FIELDS):
            return True
    return False


def _strict_first_byte_errors(
    evidence: Mapping[str, Any],
    records: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    require_case: bool,
) -> list[str]:
    errors = first_byte_evidence_errors(
        evidence, require_real_host=True, require_complete_proof=True
    )
    if require_case and not _passed_case(records, "phase4_first_byte_before_response_end"):
        errors.append("phase4_first_byte_before_response_end lacks a live canonical PASS")
    if not _matching_first_byte_event(events, evidence):
        errors.append("no phase-4 rule-1100301 event matches the first-byte barrier evidence")
    return errors


def first_byte_errors(run_dir: Path, *, require_case: bool = True) -> list[str]:
    result, _manifest, evidence, errors = _first_byte_artifact(run_dir)
    if result is None:
        return errors
    connector = str(result.get("connector") or "")
    errors.extend(_canonical_base_errors(run_dir, connector))
    if evidence is None:
        return errors
    # A synthetic barrier is required as a payload-free full-lifecycle
    # artifact even when a selected native host cannot promote P4 streaming
    # capability.  Validate that bounded artifact in every run, but require a
    # real complete proof only when the result actually claims first-byte
    # evidence through a live case or a verified capability.
    errors.extend(first_byte_evidence_errors(evidence))
    records, record_errors = _case_records(run_dir)
    events, event_errors = _events(run_dir)
    errors.extend(record_errors)
    errors.extend(event_errors)
    if _requires_first_byte_proof(result, records):
        errors.extend(
            _strict_first_byte_errors(
                evidence,
                records,
                events,
                require_case=require_case,
            )
        )
    return errors


def no_full_response_buffering_errors(run_dir: Path) -> list[str]:
    errors = first_byte_errors(run_dir, require_case=True)
    result, _manifest, evidence, artifact_errors = _first_byte_artifact(run_dir)
    # Avoid duplicate diagnostics already returned by first_byte_errors.
    if result is None or artifact_errors or evidence is None:
        return errors
    records, record_errors = _case_records(run_dir)
    errors.extend(record_errors)
    if not _requires_no_buffer_proof(result, records):
        return errors
    events, event_errors = _events(run_dir)
    errors.extend(event_errors)
    errors.extend(
        _strict_first_byte_errors(
            evidence,
            records,
            events,
            require_case=False,
        )
    )
    if evidence.get("no_full_response_buffering") is not True:
        errors.append("first-byte evidence must set no_full_response_buffering=true")
    if evidence.get("connector_owned_full_response_buffer") is not False:
        errors.append(
            "first-byte evidence must set connector_owned_full_response_buffer=false"
        )
    if not _passed_case(records, "phase4_no_full_response_buffering"):
        errors.append("phase4_no_full_response_buffering lacks a live canonical PASS")
    if not any(
        no_crs.normalize_canonical_phase(event.get("phase")) == 4
        and event.get("rule_id") in {1100301, "1100301"}
        and event.get("no_full_response_buffering") is True
        for event in events
    ):
        errors.append("no phase-4 event establishes no_full_response_buffering=true")
    return errors


def event_privacy_errors(run_dir: Path) -> list[str]:
    result, _manifest, evidence, errors = _first_byte_artifact(run_dir)
    if result is None:
        return errors
    errors.extend(_canonical_base_errors(run_dir, str(result.get("connector") or "")))
    errors.extend(no_crs.body_payload_errors(run_dir))
    if evidence is not None:
        errors.extend(first_byte_evidence_errors(evidence))
    return errors


def promotion_errors(run_dir: Path) -> list[str]:
    result, _manifest, evidence, errors = _first_byte_artifact(run_dir)
    if result is None or evidence is None:
        return errors
    errors.extend(_canonical_base_errors(run_dir, str(result.get("connector") or "")))
    records, record_errors = _case_records(run_dir)
    errors.extend(record_errors)
    claimed_cases = {
        str(record.get("case_id"))
        for record in records
        if record.get("case_id") in FULL_LIFECYCLE_CASES and record.get("status") == "PASS"
    }
    raw_capabilities = result.get("capabilities_verified", [])
    claimed_capabilities = (
        set(str(value) for value in raw_capabilities)
        if isinstance(raw_capabilities, list)
        else set()
    )
    protected_capabilities = {
        "first_byte_before_response_end",
        "no_full_response_buffering",
    }
    if evidence.get("evidence_origin") != "real_host":
        if claimed_cases:
            errors.append(
                "synthetic first-byte evidence cannot support PASS cases: "
                + ", ".join(sorted(claimed_cases))
            )
        leaked = sorted(claimed_capabilities.intersection(protected_capabilities))
        if leaked:
            errors.append(
                "synthetic first-byte evidence cannot promote capabilities: "
                + ", ".join(leaked)
            )
        return errors
    if claimed_cases or claimed_capabilities.intersection(protected_capabilities):
        errors.extend(first_byte_errors(run_dir, require_case=True))
        if (
            "phase4_no_full_response_buffering" in claimed_cases
            or "no_full_response_buffering" in claimed_capabilities
        ):
            errors.extend(no_full_response_buffering_errors(run_dir))
    return errors


CHECKS = {
    "first-byte": first_byte_errors,
    "no-full-response-buffering": no_full_response_buffering_errors,
    "event-privacy": event_privacy_errors,
    "promotion": promotion_errors,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--check", required=True, choices=sorted(CHECKS))
    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir)
    errors = CHECKS[args.check](run_dir)
    if errors:
        for error in errors:
            print(f"full-lifecycle-evidence: {args.check}: {error}", file=sys.stderr)
        return 1
    print(f"full-lifecycle-evidence: {args.check}: PASS ({run_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
