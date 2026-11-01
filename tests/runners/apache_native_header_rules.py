"""Adapt one immutable case to Apache's ordered, core-merged header view.

Apache supplies ``headers_in`` after case-insensitive APR table compression.
The adapter can test the resulting ordered value, but cannot recover the wire
occurrence count. A singleton ``one, two`` is indistinguishable in that view.
This is test setup, never evidence that the host or its audit sink executed.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib


PROFILE = "apache-native"
CASE_NAME = "duplicate_header_names"
CASE_SHA256 = "502f7fc36219912d89f492493e50fe32d9cf191e6802d7163ea3c22143ad5731"
ORIGINAL_RULE = '''SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 2" \\
    "id:1100504,phase:1,pass,log,t:none,chain,msg:'no-crs duplicate request header names'"
SecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq one" "t:none,chain"
SecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq two" "t:none"'''
NATIVE_RULE = '''SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 1" \\
    "id:1100504,phase:1,pass,log,t:none,chain,msg:'no-crs duplicate request header names'"
SecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq one, two" "t:none"'''


def _exact(value: object, expected: object) -> bool:
    return type(value) is type(expected) and value == expected


def _validate_original(case: Mapping[str, object], case_sha256: str) -> str:
    if case_sha256 != CASE_SHA256:
        raise ValueError("Apache native adapter requires the immutable original case SHA-256")
    original = case.get("rules")
    if not isinstance(original, str) or original.count(ORIGINAL_RULE) != 1:
        raise ValueError("Apache native adapter requires the exact original rule block")
    request, expect = case.get("request"), case.get("expect")
    if not isinstance(request, Mapping) or not isinstance(expect, Mapping):
        raise ValueError("Apache native adapter requires original request and expectations")
    headers = [{"name": "X-No-Crs-Duplicate", "value": value} for value in ("one", "two")]
    if (request.get("headers") != headers or request.get("method") != "GET"
            or request.get("path") != "/no-crs/headers/duplicate"):
        raise ValueError("Apache native adapter requires original ordered duplicate headers")
    audit = expect.get("audit_log")
    required = {"status": 200, "intervention": "none", "rule_id": 1100504}
    if (not all(_exact(expect.get(key), value) for key, value in required.items())
            or not isinstance(audit, Mapping)
            or audit.get("required") is not True
            or not _exact(audit.get("rule_id"), 1100504)
            or audit.get("message") != "no-crs duplicate request header names"
            or not _exact(case.get("expected_status"), 200)
            or not _exact(case.get("expected_rule_id"), 1100504)
            or case.get("no_crs_baseline") is not True):
        raise ValueError("Apache native adapter must retain HTTP 200, rule 1100504 and audit assertions")
    return original


def adapt_native_case(
    case: Mapping[str, object], *, profile: str, case_sha256: str
) -> tuple[dict[str, object], dict[str, object] | None]:
    """Return an independent host fixture and a non-promoting adaptation receipt.

    The caller archives the original rendered rules and writes the receipt using
    its normal contained output API. Other cases retain their portable rules.
    The source case, wire headers and every expected assertion stay unchanged.
    """
    if profile != PROFILE:
        raise ValueError("unsupported native header adapter profile")
    adapted = deepcopy(dict(case))
    if case.get("name") != CASE_NAME:
        return adapted, None
    original = _validate_original(case, case_sha256)
    corrected = original.replace(ORIGINAL_RULE, NATIVE_RULE)
    adapted["rules"] = corrected
    return adapted, {
        "schema_version": 1,
        "adapter": "apache_core_merged_duplicate_headers_v1",
        "profile": PROFILE,
        "case_id": CASE_NAME,
        "original_case_sha256": case_sha256,
        "original_source_rules_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "native_source_rules_sha256": hashlib.sha256(corrected.encode()).hexdigest(),
        "native_header_count": 1,
        "native_ordered_value": "one, two",
        "unchanged_expectations": {"http_status": 200, "rule_id": 1100504, "audit_required": True},
        "original_oracle_preserved": True,
        "wire_occurrence_count_observable": False,
        "runtime_retest": None,
        "lifecycle_qualification": None,
    }
