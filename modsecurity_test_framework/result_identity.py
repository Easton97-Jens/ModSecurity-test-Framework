"""Public, payload-free identity contract for connector test observations."""
from __future__ import annotations

import re
import hashlib
import json
from typing import Any, Mapping


RESULT_BINDING_FIELDS = ("run_id", "case_id", "request_id", "transaction_id", "source_revision")


def validate_result_context(binding: Mapping[str, Any]) -> dict[str, str]:
    """Validate source/run/case context, including a case that did not start."""
    validated: dict[str, str] = {}
    for field in ("run_id", "case_id", "source_revision"):
        value = binding.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9:._/-]{1,256}", value) is None:
            raise ValueError(f"result identity requires a bounded explicit {field}")
        validated[field] = value
    if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", validated["source_revision"]) is None:
        raise ValueError("result identity requires an exact source revision")
    return validated


def validate_result_binding(binding: Mapping[str, Any]) -> dict[str, str]:
    """Validate an explicit request/transaction binding, without guessing IDs."""
    validated = validate_result_context(binding)
    for field in ("request_id", "transaction_id"):
        value = binding.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9:._/-]{1,256}", value) is None:
            raise ValueError(f"result identity requires a bounded explicit {field}")
        validated[field] = value
    return validated


def validate_request_observation(binding: Mapping[str, Any]) -> dict[str, str]:
    """Validate the explicit, non-promoting completed-client observation mode."""
    validated = validate_result_context(binding)
    request = binding.get("request_id")
    if not isinstance(request, str) or re.fullmatch(r"request-[0-9a-f]{32}", request) is None:
        raise ValueError("request observation requires its own bounded request nonce")
    validated["request_id"] = request
    if (binding.get("evidence_identity") != "request_bound"
            or binding.get("transaction_id") is not None or binding.get("transaction_ids") != []
            or binding.get("runtime_verified") is not False or binding.get("promotion_allowed") is not False
            or binding.get("live_executed") is not True or str(binding.get("status")).lower() not in {"pass", "fail"}
            or type(binding.get("actual_status")) is not int or not 100 <= binding["actual_status"] <= 599):
        raise ValueError("request observation must remain client-only and non-promoting")
    if any(binding.get(field) is not None for field in (
            "native_operation_receipt", "configtest_receipt", "first_byte_binding_path", "first_byte_evidence_path")):
        raise ValueError("client observation cannot claim native host evidence")
    proof = binding.get("request_observation")
    if not isinstance(proof, dict) or proof.get("state") != "completed" or proof.get("schema_version") != 2:
        raise ValueError("request observation requires a completed pinned window receipt")
    for field in ("run_id", "case_id", "request_id", "source_revision"):
        if proof.get(field) != validated[field]:
            raise ValueError("request observation nonce or context differs from its receipt")
    for field in ("receipt_sha256", "begin_sha256", "case_sha256", "prefix_sha256", "interval_sha256"):
        if not isinstance(proof.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", proof[field]) is None:
            raise ValueError("request observation requires complete receipt digests")
    start, end = proof.get("start_offset"), proof.get("end_offset")
    if type(start) is not int or type(end) is not int or not 0 <= start <= end:
        raise ValueError("request observation requires bounded completed interval offsets")
    fields = {"schema_version", "state", "run_id", "case_id", "request_id", "source_revision",
              "event_log", "case_sha256", "begin_sha256", "prefix_sha256", "interval_sha256",
              "start_offset", "end_offset", "receipt_sha256"}
    if set(proof) != fields:
        raise ValueError("request observation receipt fields are incomplete")
    receipt = {key: value for key, value in proof.items() if key != "receipt_sha256"}
    raw = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != proof["receipt_sha256"]:
        raise ValueError("request observation receipt digest does not bind its nonce and context")
    begin_fields = ("schema_version", "run_id", "case_id", "request_id", "source_revision",
                    "event_log", "case_sha256", "start_offset", "prefix_sha256")
    begin = {field: proof[field] for field in begin_fields}
    begin["state"] = "begun"
    if hashlib.sha256((json.dumps(begin, sort_keys=True) + "\n").encode()).hexdigest() != proof["begin_sha256"]:
        raise ValueError("request observation begin digest does not bind its nonce and context")
    return validated


def validate_summary_identity(run_id: Any = None, source_revision: Any = None) -> dict[str, str]:
    """Validate an optional expected bundle identity without inventing a run."""
    values: dict[str, str] = {}
    for field, value in (("run_id", run_id), ("source_revision", source_revision)):
        if value in (None, ""):
            continue
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9:._/-]{1,256}", value) is None:
            raise ValueError(f"summary requires a bounded explicit {field} identity")
        if field == "source_revision" and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value) is None:
            raise ValueError("summary requires an exact source revision identity")
        values[field] = value
    return values
