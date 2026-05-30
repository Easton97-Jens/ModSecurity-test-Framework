#!/usr/bin/env python3
"""Shared RESPONSE_BODY non-promotion helpers for runtime reports."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import re
from typing import Any


RESPONSE_BODY_EVIDENCE_NOTE = (
    "RESPONSE_BODY pass-through evidence only; not proof of response-body blocking/inspection."
)
RESPONSE_BODY_RUNTIME_NOTE = "Runtime passed, but this does not verify RESPONSE_BODY support."
RESPONSE_BODY_PASS_THROUGH_STATUS = "RESPONSE_BODY_PASS_THROUGH"

_SECRULE_VARIABLE_RE = re.compile(r"^\s*SecRule\s+([^\s]+)", re.MULTILINE)
_RESPONSE_BODY_MARKERS = ("response_body", "response-body")


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return " ".join(f"{key} {_flatten_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)


def _contains_marker(value: Any, markers: tuple[str, ...] = _RESPONSE_BODY_MARKERS) -> bool:
    text = _flatten_text(value).lower()
    return any(marker in text for marker in markers)


def _normalized_token(value: Any) -> str:
    return str(value).strip().replace("_", "-").lower()


def _capability_names(capabilities: Any) -> list[str]:
    if isinstance(capabilities, Mapping):
        raw = [key for key, value in capabilities.items() if bool_value(value)]
    elif isinstance(capabilities, list):
        raw = capabilities
    else:
        return []
    return [_normalized_token(item) for item in raw if str(item).strip()]


def _variable_base(value: Any) -> str:
    token = str(value).strip().lstrip("!&")
    token = token.split(":", 1)[0]
    return token.upper()


def variables_from_rules(rules: str) -> list[str]:
    variables: list[str] = []
    for match in _SECRULE_VARIABLE_RE.finditer(rules):
        for part in match.group(1).split("|"):
            if part.strip():
                variables.append(part.strip())
    return variables


def case_variables(case: Mapping[str, Any]) -> list[str]:
    raw_variables = case.get("variables", [])
    if isinstance(raw_variables, str):
        variables = [raw_variables]
    elif isinstance(raw_variables, list):
        variables = [str(item) for item in raw_variables]
    else:
        variables = []
    variables.extend(variables_from_rules(str(case.get("rules", "") or "")))
    return variables


def has_response_body_variable(case: Mapping[str, Any]) -> bool:
    return any(_variable_base(variable) == "RESPONSE_BODY" for variable in case_variables(case))


def has_response_body_capability(case: Mapping[str, Any]) -> bool:
    return "response-body" in _capability_names(case.get("capabilities"))


def is_response_body_related(case: Mapping[str, Any] | None, path: str | Path | None = None) -> bool:
    case_data = case if isinstance(case, Mapping) else {}
    if has_response_body_variable(case_data):
        return True
    if has_response_body_capability(case_data):
        return True
    if _contains_marker(case_data.get("known_limitations")):
        return True

    name_path_parts = [
        case_data.get("name", ""),
        case_data.get("id", ""),
        case_data.get("path", ""),
        "" if path is None else str(path),
    ]
    if _contains_marker(" ".join(str(part) for part in name_path_parts), ("response_body",)):
        return True

    metadata_parts = [
        case_data.get("tags", ""),
        case_data.get("notes", case_data.get("note", "")),
        case_data.get("category", ""),
    ]
    return _contains_marker(metadata_parts)


def response_body_pass_through_status(classification: str) -> str:
    normalized = str(classification or "active").strip().lower()
    prefixes = {
        "active": "",
        "connector_gap": "CONNECTOR_GAP_",
        "runtime_difference": "RUNTIME_DIFFERENCE_",
        "pending": "PENDING_",
        "future": "FUTURE_",
        "xfail": "XFAIL_",
    }
    return f"{prefixes.get(normalized, 'XFAIL_')}{RESPONSE_BODY_PASS_THROUGH_STATUS}"


def matrix_status_for_result(
    result_status: str,
    classification: str,
    *,
    response_body_related: bool = False,
) -> str:
    status = result_status.strip().lower()
    if status == "blocked":
        return "BLOCKED"
    if status == "skipped":
        return "NOT_EXECUTABLE"
    if status == "xfail":
        return "XFAIL_FAIL"
    if status not in {"pass", "fail"}:
        return status.upper() if status else "UNKNOWN"
    if status == "pass" and response_body_related:
        return response_body_pass_through_status(classification)

    suffix = "PASS" if status == "pass" else "FAIL"
    normalized = str(classification or "active").strip().lower()
    if normalized == "active":
        return suffix
    if normalized == "connector_gap":
        return f"CONNECTOR_GAP_{suffix}"
    if normalized == "runtime_difference":
        return f"RUNTIME_DIFFERENCE_{suffix}"
    if normalized == "pending":
        return f"PENDING_{suffix}"
    if normalized == "future":
        return f"FUTURE_{suffix}"
    return f"XFAIL_{suffix}"


def response_body_non_promotion_fields(response_body_related: bool, classification: str) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "not_auto_promoted": response_body_related or str(classification).strip().lower() != "active",
    }
    if response_body_related:
        fields.update(
            {
                "response_body_non_verified": True,
                "runtime_verified": False,
                "promotion_allowed": False,
                "evidence_note": RESPONSE_BODY_EVIDENCE_NOTE,
            }
        )
    return fields
