#!/usr/bin/env python3
"""Validate the fixed security-data-flow case inventory."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "tests" / "cases" / "security-data-flow"
REQUIRED = (
    "headers/header_count_limit_exceeded.yaml",
    "headers/header_value_limit_exceeded.yaml",
    "headers/conflicting_content_length_rejected.yaml",
    "body-limits/request_body_limit_exceeded.yaml",
    "body-limits/response_body_truncation_event.yaml",
    "transaction-id/transaction_id_control_char_rejected.yaml",
    "transaction-id/transaction_id_too_long_rejected.yaml",
    "events/decision_jsonl_no_body_payload.yaml",
    "events/event_jsonl_no_body_payload.yaml",
    "events/integrity_event_hash_chain_valid.yaml",
    "events/integrity_event_hash_chain_tamper_detected.yaml",
    "phase-order/phase_skip_rejected.yaml",
    "phase-order/duplicate_mutating_phase_rejected.yaml",
    "log-safety/log_control_chars_sanitized.yaml",
    "log-safety/log_secret_like_payload_redacted.yaml",
)
SECRET_PATTERNS = (
    r"AWS_SECRET",
    r"BEGIN PRIVATE KEY",
    r"sk-[A-Za-z0-9]",
    r"password=real",
    r"token=real",
)
BODY_FIELDS = ("request_body", "response_body", "body_payload", "raw_body", "payload")
CASE_NAME_RE = re.compile(r"^name:\s*([A-Za-z0-9_.-]+)\s*$", re.MULTILINE)
METADATA_RE = re.compile(r"^(description|known_limitations|former_xfail_reason):", re.MULTILINE)
RUNTIME_VERIFIED_RE = re.compile(r"runtime_verified:\s*true", re.IGNORECASE)
AUTOMATIC_STATUS_RE = re.compile(
    r"status:\s*(passed|pass|runtime-verified|verified)", re.IGNORECASE
)
MAX_LINE_LENGTH = 4096
MAX_CASE_BYTES = 20000


def case_name_errors(path: Path, text: str, names: dict[str, Path]) -> list[str]:
    """Require a unique, bounded case name while preserving the inventory map."""

    match = CASE_NAME_RE.search(text)
    if match is None:
        return [f"{path}: missing name"]
    name = match.group(1)
    if name in names:
        return [f"{path}: duplicate name {name}"]
    names[name] = path
    return []


def content_contract_errors(path: Path, text: str) -> list[str]:
    """Check required metadata and reject secrets or oversized inline data."""

    errors: list[str] = []
    if "security-data-flow" not in text:
        errors.append(f"{path}: missing security-data-flow tag")
    if METADATA_RE.search(text) is None:
        errors.append(f"{path}: missing description/metadata")
    errors.extend(
        f"{path}: possible real secret pattern {pattern}"
        for pattern in SECRET_PATTERNS
        if re.search(pattern, text)
    )
    if any(len(line) > MAX_LINE_LENGTH for line in text.splitlines()) or len(text) > MAX_CASE_BYTES:
        errors.append(f"{path}: possible huge inline payload")
    return errors


def event_payload_errors(path: Path, text: str) -> list[str]:
    """Forbid expected body payload fields in event/decision fixture inputs."""

    if "/events/" not in path.as_posix():
        return []
    forbidden = [
        field
        for field in BODY_FIELDS
        if re.search(rf"^\s*{re.escape(field)}\s*:", text, re.MULTILINE)
    ]
    if not forbidden:
        return []
    return [f"{path}: event/decision case contains expected body payload fields {forbidden}"]


def promotion_errors(path: Path, text: str) -> list[str]:
    """Keep security-data-flow fixture expectations non-promoted by default."""

    errors: list[str] = []
    if RUNTIME_VERIFIED_RE.search(text):
        errors.append(f"{path}: must not be runtime_verified")
    if AUTOMATIC_STATUS_RE.search(text):
        errors.append(f"{path}: must not be automatically runtime verified")
    return errors


def validate_case(path: Path, names: dict[str, Path]) -> list[str]:
    """Validate one required fixture against all security-data-flow contracts."""

    if not path.exists():
        return [f"missing {path}"]
    text = path.read_text(encoding="utf-8")
    errors = case_name_errors(path, text, names)
    errors.extend(content_contract_errors(path, text))
    errors.extend(event_payload_errors(path, text))
    errors.extend(promotion_errors(path, text))
    return errors


def main() -> int:
    names: dict[str, Path] = {}
    errors = [error for relative_path in REQUIRED for error in validate_case(BASE / relative_path, names)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"OK: {len(REQUIRED)} security-data-flow cases validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
