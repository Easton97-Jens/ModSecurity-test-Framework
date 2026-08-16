#!/usr/bin/env python3
"""Validate and reconcile the typed common-version review plan.

The resolver owns the plan; this module deliberately does not discover
upstream data.  Keeping validation and GitHub mutation here makes the
publisher job small and gives tests a completely injectable client boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlencode
from urllib.request import Request, urlopen


SCHEMA_VERSION = "1"
MAX_PLAN_BYTES = 1_000_000
MAX_STRING = 512
MAX_REASON = 2_000
MAX_ITEMS = 256
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
URL_RE = re.compile(
    r"^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?$"
)
COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SHELL_VARIABLE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
IDENTITY_KEYS = {
    "version",
    "tag",
    "commit",
    "repository",
    "asset",
    "digest",
    "series",
    "provider",
    "platform",
}
MANDATORY_GLOBAL_COMPONENTS = (
    "go-ftw",
    "albedo",
    "python",
    "pyyaml",
    "node",
    "github-actions",
    "ci-security-tools",
)
REVIEW_KINDS = {
    "series_transition",
    "major_version_transition",
    "minor_version_transition",
    "release_commit_provenance",
    "provider_transition",
    "artifact_layout_transition",
    "platform_transition",
    "manual_digest_verification",
    "runtime_compatibility_review",
    "ci_runtime_transition",
}
REVIEW_STATES = {"active", "completed", "superseded", "withdrawn"}
OUTCOMES = {
    "no_updates",
    "manual_review_only",
    "safe_updates",
    "safe_updates_with_manual_review",
    "fatal",
}
FIXED_LABELS = ("maintenance", "dependencies", "manual-review", "common-version")
ALLOWED_LABEL_RE = re.compile(
    r"^(?:maintenance|dependencies|manual-review|common-version|component:[a-z0-9][a-z0-9._-]{0,63})$"
)
PLAN_FILENAME = "canonical-maintenance-plan.json"


class PlanError(ValueError):
    """A plan failed closed validation."""


def _bounded(value: Any, field: str, limit: int = MAX_STRING) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise PlanError(f"{field} must be a non-empty bounded string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PlanError(f"{field} contains control characters")
    return value


def _list(value: Any, field: str, maximum: int = MAX_ITEMS) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise PlanError(f"{field} must be a bounded array")
    return value


def _slug(value: Any, field: str) -> str:
    value = _bounded(value, field, 64)
    if not COMPONENT_RE.fullmatch(value):
        raise PlanError(f"{field} is not a stable component slug")
    return value


def _identity(value: Any, field: str) -> Dict[str, str]:
    if not isinstance(value, dict) or not value or set(value) - IDENTITY_KEYS:
        raise PlanError(f"{field} must contain only checked identity fields")
    result = {}
    for key, item in value.items():
        result[_bounded(key, f"{field} key", 32)] = _bounded(item, f"{field}.{key}")
    return result


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _plan_digest(plan: Mapping[str, Any]) -> str:
    unsigned = dict(plan)
    unsigned.pop("plan_sha256", None)
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _safe_value(value: Any, field: str, depth: int = 0) -> Any:
    """Validate bounded summary data without permitting executable content."""
    if depth > 3:
        raise PlanError(f"{field} is nested too deeply")
    if isinstance(value, str):
        return _bounded(value, field)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if value < -1_000_000_000 or value > 1_000_000_000:
            raise PlanError(f"{field} contains an unbounded integer")
        return value
    if isinstance(value, list):
        return [
            _safe_value(item, f"{field}[{index}]", depth + 1)
            for index, item in enumerate(_list(value, field, 64))
        ]
    if isinstance(value, dict):
        return _safe_mapping(value, field, depth)
    raise PlanError(f"{field} contains an unsupported value")


def _safe_mapping(value: dict, field: str, depth: int) -> dict:
    if len(value) > 64:
        raise PlanError(f"{field} contains too many properties")
    result = {}
    for key, item in value.items():
        safe_key = _bounded(key, f"{field} key", 128)
        if re.fullmatch(r"[A-Za-z0-9_.:-]+", safe_key) is None:
            raise PlanError(f"{field} contains an unsafe property name")
        result[safe_key] = _safe_value(item, f"{field}.{safe_key}", depth + 1)
    return result


def _relative_path(value: Any, field: str) -> str:
    path = _bounded(value, field, 256)
    parts = path.split("/")
    if (
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PlanError(f"{field} must be a safe repository-relative path")
    return path


def _component_result_base(value: Any, index: int) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise PlanError(f"component_results[{index}] must be an object")
    allowed = {
        "component_id",
        "component_name",
        "scope",
        "status",
        "message",
        "canonical_variables",
        "current",
        "latest_compatible",
        "latest_upstream",
        "source",
        "updates",
        "details",
    }
    if set(value) - allowed or not {
        "component_id",
        "component_name",
        "scope",
        "status",
        "message",
        "canonical_variables",
    } <= set(value):
        raise PlanError(f"component_results[{index}] has an invalid field set")
    component = _slug(value["component_id"], f"component_results[{index}].component_id")
    return {
        "component_id": component,
        "component_name": _bounded(
            value["component_name"], f"component_results[{index}].component_name", 128
        ),
        "scope": _slug(value["scope"], f"component_results[{index}].scope"),
        "status": _bounded(value["status"], f"component_results[{index}].status", 32),
        "message": _bounded(
            value["message"], f"component_results[{index}].message", MAX_REASON
        ),
        "canonical_variables": [
            _bounded(item, f"component_results[{index}].canonical_variables", 128)
            for item in _list(
                value["canonical_variables"],
                f"component_results[{index}].canonical_variables",
                64,
            )
        ],
    }


def _component_result_optional(
    value: Mapping[str, Any], index: int, result: Dict[str, Any]
) -> Dict[str, Any]:
    for field in ("current", "latest_compatible", "latest_upstream", "source"):
        if field in value:
            result[field] = _bounded(
                value[field], f"component_results[{index}].{field}"
            )
    if (
        "source" in result
        and result["source"]
        and not URL_RE.fullmatch(result["source"])
    ):
        raise PlanError("component_results source must be HTTPS")
    if "details" in value:
        result["details"] = _safe_value(
            value["details"], f"component_results[{index}].details"
        )
    return result


def _component_result_updates(
    value: Mapping[str, Any], index: int, result: Dict[str, Any]
) -> Dict[str, Any]:
    if "updates" not in value:
        return result
    updates = _list(value["updates"], f"component_results[{index}].updates", 64)
    normalized = []
    for update_index, update in enumerate(updates):
        if not isinstance(update, dict) or set(update) != {"variable", "old", "new"}:
            raise PlanError(
                f"component_results[{index}].updates[{update_index}] is invalid"
            )
        variable = _bounded(update["variable"], "component result update variable", 128)
        if SHELL_VARIABLE_RE.fullmatch(variable) is None:
            raise PlanError("component result update variable is unsafe")
        normalized.append(
            {
                "variable": variable,
                "old": _bounded(update["old"], "component result old"),
                "new": _bounded(update["new"], "component result new"),
            }
        )
    result["updates"] = normalized
    return result


def _component_result(value: Any, index: int) -> Dict[str, Any]:
    result = _component_result_base(value, index)
    if any(
        SHELL_VARIABLE_RE.fullmatch(item) is None
        for item in result["canonical_variables"]
    ):
        raise PlanError(
            "component_results canonical_variables must be shell variable names"
        )
    result = _component_result_optional(value, index, result)
    return _component_result_updates(value, index, result)


def _safe_update(value: Any, index: int) -> Dict[str, str]:
    """Validate one bounded, data-only canonical update.

    The resolver is the only producer of these records.  Keeping the same
    shape validation in the reconciler means validate-only and publisher jobs
    share the exact schema boundary without importing a third-party package.
    """
    if not isinstance(value, dict) or set(value) != {"variable", "old", "new"}:
        raise PlanError(f"safe_updates[{index}] is invalid")
    variable = _bounded(value["variable"], f"safe_updates[{index}].variable", 128)
    if SHELL_VARIABLE_RE.fullmatch(variable) is None:
        raise PlanError(f"safe_updates[{index}].variable is unsafe")
    return {
        "variable": variable,
        "old": _bounded(value["old"], f"safe_updates[{index}].old", 240),
        "new": _bounded(value["new"], f"safe_updates[{index}].new", 240),
    }


def _generated_view_status(value: Any, index: int) -> Dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) - {"name", "status", "message"}
        or not {"name", "status"} <= set(value)
    ):
        raise PlanError(f"generated_view_status[{index}] is invalid")
    status = _bounded(value["status"], f"generated_view_status[{index}].status", 32)
    if status not in {"current", "blocked", "unknown", "error"}:
        raise PlanError(f"generated_view_status[{index}] has an invalid status")
    result = {
        "name": _bounded(value["name"], f"generated_view_status[{index}].name", 128),
        "status": status,
    }
    if "message" in value:
        result["message"] = _bounded(
            value["message"], f"generated_view_status[{index}].message", MAX_REASON
        )
    return result


def _validate_plan_header(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    allowed = {
        "schema_version",
        "maintenance_outcome",
        "global_inventory_complete",
        "scope",
        "safe_updates",
        "manual_reviews",
        "checked_components",
        "generated_views",
        "component_results",
        "generated_view_status",
        "source_common_sha256",
        "candidate_common_sha256",
        "plan_sha256",
    }
    if set(plan) - allowed:
        raise PlanError("plan contains unsupported fields")
    if plan.get("schema_version") != SCHEMA_VERSION:
        raise PlanError("unsupported schema_version")
    if plan.get("maintenance_outcome") not in OUTCOMES:
        raise PlanError("invalid maintenance_outcome")
    if "global_inventory_complete" in plan and not isinstance(
        plan["global_inventory_complete"], bool
    ):
        raise PlanError("global_inventory_complete must be boolean")
    for digest_field in (
        "source_common_sha256",
        "candidate_common_sha256",
        "plan_sha256",
    ):
        digest = plan.get(digest_field)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise PlanError(f"{digest_field} must be a lowercase SHA-256")
    return plan


def _validate_plan_scope(plan: Mapping[str, Any]) -> list[str]:
    scope = plan.get("scope")
    if not isinstance(scope, dict) or set(scope) != {"mode", "checked_components"}:
        raise PlanError("scope must contain mode and checked_components")
    if scope["mode"] not in {"full", "component"}:
        raise PlanError("invalid scope mode")
    checked = [
        _slug(item, "scope.checked_components")
        for item in _list(scope["checked_components"], "scope.checked_components")
    ]
    if not checked or len(set(checked)) != len(checked):
        raise PlanError("scope components must be a non-empty unique list")
    if not set(MANDATORY_GLOBAL_COMPONENTS).issubset(checked):
        raise PlanError("scope must include every mandatory global component")
    top_checked = [
        _slug(item, "checked_components")
        for item in _list(plan.get("checked_components"), "checked_components")
    ]
    if top_checked != checked:
        raise PlanError("checked_components must match scope")
    return checked


def _validate_plan_collections(
    plan: Mapping[str, Any], checked: Sequence[str]
) -> tuple[
    list[str],
    list[Dict[str, str]],
    list[Dict[str, Any]],
    list[Dict[str, Any]],
    list[Dict[str, Any]],
]:
    views = [
        _relative_path(item, "generated_views")
        for item in _list(plan.get("generated_views"), "generated_views")
    ]
    safe_updates = [
        _safe_update(item, index)
        for index, item in enumerate(_list(plan.get("safe_updates"), "safe_updates"))
    ]
    normalized = []
    keys = set()
    for index, review in enumerate(_list(plan.get("manual_reviews"), "manual_reviews")):
        normalized.append(_validate_review(review, index, checked, keys))
    component_results = [
        _component_result(item, index)
        for index, item in enumerate(
            _list(plan.get("component_results", []), "component_results")
        )
    ]
    generated_status = [
        _generated_view_status(item, index)
        for index, item in enumerate(
            _list(plan.get("generated_view_status", []), "generated_view_status")
        )
    ]
    return views, safe_updates, normalized, component_results, generated_status


def validate_plan(plan: Any) -> Dict[str, Any]:
    if not isinstance(plan, dict):
        raise PlanError("plan must be an object")
    _validate_plan_header(plan)
    checked = _validate_plan_scope(plan)
    views, safe_updates, normalized, component_results, generated_status = (
        _validate_plan_collections(plan, checked)
    )
    if plan["plan_sha256"] != _plan_digest(plan):
        raise PlanError("plan_sha256 does not match canonical plan")
    result = dict(plan)
    result["scope"] = {"mode": plan["scope"]["mode"], "checked_components": checked}
    result["checked_components"] = checked
    result["generated_views"] = views
    result["safe_updates"] = safe_updates
    result["manual_reviews"] = normalized
    if "component_results" in plan:
        result["component_results"] = component_results
    if "generated_view_status" in plan:
        result["generated_view_status"] = generated_status
    return result


def _review_header(
    review: Mapping[str, Any], index: int, checked: Sequence[str], keys: set
) -> tuple[str, str, str, str]:
    required = {
        "review_key",
        "component_id",
        "component_name",
        "review_kind",
        "current_identity",
        "candidate_identity",
        "latest_compatible",
        "latest_upstream",
        "canonical_variables",
        "reason_code",
        "reason",
        "evidence_urls",
        "automatic_update_also_available",
    }
    optional = {"state", "lifecycle_evidence", "generated_views"}
    if set(review) - required - optional or not required <= set(review):
        raise PlanError(f"manual_reviews[{index}] has an invalid field set")
    component = _slug(review["component_id"], f"manual_reviews[{index}].component_id")
    if component not in checked:
        raise PlanError(f"review component {component} is outside the checked scope")
    key = _bounded(review["review_key"], f"manual_reviews[{index}].review_key", 160)
    if not KEY_RE.fullmatch(key) or key in keys:
        raise PlanError(f"review_key is invalid or duplicated: {key}")
    keys.add(key)
    kind = _bounded(review["review_kind"], f"manual_reviews[{index}].review_kind", 64)
    if kind not in REVIEW_KINDS:
        raise PlanError(f"unsupported review_kind: {kind}")
    name = _bounded(
        review["component_name"], f"manual_reviews[{index}].component_name", 128
    )
    return component, key, kind, name


def _review_identities(
    review: Mapping[str, Any], index: int
) -> tuple[Dict[str, str], Dict[str, str], str, str, list[str]]:
    current = _identity(
        review["current_identity"], f"manual_reviews[{index}].current_identity"
    )
    candidate = _identity(
        review["candidate_identity"], f"manual_reviews[{index}].candidate_identity"
    )
    compatible = _bounded(
        review["latest_compatible"], f"manual_reviews[{index}].latest_compatible"
    )
    upstream = _bounded(
        review["latest_upstream"], f"manual_reviews[{index}].latest_upstream"
    )
    variables = [
        _bounded(item, "canonical_variables", 128)
        for item in _list(review["canonical_variables"], "canonical_variables", 64)
    ]
    if any(SHELL_VARIABLE_RE.fullmatch(item) is None for item in variables):
        raise PlanError("canonical_variables must be canonical shell variable names")
    return current, candidate, compatible, upstream, variables


def _review_metadata(
    review: Mapping[str, Any], index: int
) -> tuple[str, str, list[str], bool, str, Any]:
    reason_code = _bounded(
        review["reason_code"], f"manual_reviews[{index}].reason_code", 64
    )
    reason = _bounded(review["reason"], f"manual_reviews[{index}].reason", MAX_REASON)
    evidence = [
        _bounded(item, "evidence_urls", 512)
        for item in _list(review["evidence_urls"], "evidence_urls", 16)
    ]
    if any(not URL_RE.fullmatch(item) for item in evidence):
        raise PlanError("evidence_urls must be official HTTPS URLs")
    automatic = review["automatic_update_also_available"]
    if not isinstance(automatic, bool):
        raise PlanError("automatic_update_also_available must be boolean")
    state = review.get("state", "active")
    if state not in REVIEW_STATES:
        raise PlanError("invalid review state")
    lifecycle = review.get("lifecycle_evidence")
    _validate_lifecycle(lifecycle, state)
    return reason_code, reason, evidence, automatic, state, lifecycle


def _validate_lifecycle(lifecycle: Any, state: str) -> None:
    if state == "active":
        return
    if not isinstance(lifecycle, dict) or set(lifecycle) - {
        "reason",
        "maintenance_run",
        "verified_identity",
        "withdrawal_url",
    }:
        raise PlanError("non-active reviews require bounded lifecycle_evidence")
    _bounded(lifecycle.get("reason"), "lifecycle_evidence.reason", MAX_REASON)
    _bounded(
        lifecycle.get("maintenance_run"), "lifecycle_evidence.maintenance_run", 256
    )
    if "verified_identity" in lifecycle:
        _identity(
            lifecycle["verified_identity"], "lifecycle_evidence.verified_identity"
        )
    if "withdrawal_url" in lifecycle:
        url = _bounded(
            lifecycle["withdrawal_url"], "lifecycle_evidence.withdrawal_url", 512
        )
        if not URL_RE.fullmatch(url):
            raise PlanError("withdrawal_url must be HTTPS")


def _review_target_key(
    key: str, component: str, kind: str, candidate: Mapping[str, str]
) -> None:
    target = next(
        (
            candidate.get(field)
            for field in (
                "series",
                "tag",
                "version",
                "commit",
                "provider",
                "asset",
                "digest",
            )
            if candidate.get(field)
        ),
        None,
    )
    if not target:
        raise PlanError("review_key is not deterministic for the candidate identity")
    target_slug = (
        target.lower()
        if KEY_RE.fullmatch(target.lower())
        else hashlib.sha256(target.encode("utf-8")).hexdigest()
    )
    if key != f"{component}:{kind}:{target_slug}":
        raise PlanError("review_key is not deterministic for the candidate identity")


def _review_views(review: Mapping[str, Any], index: int) -> list[str] | None:
    if "generated_views" not in review:
        return None
    return [
        _relative_path(item, f"manual_reviews[{index}].generated_views")
        for item in _list(
            review["generated_views"], f"manual_reviews[{index}].generated_views"
        )
    ]


def _validate_review(
    review: Any, index: int, checked: Sequence[str], keys: set
) -> Dict[str, Any]:
    if not isinstance(review, dict):
        raise PlanError(f"manual_reviews[{index}] must be an object")
    component, key, kind, name = _review_header(review, index, checked, keys)
    current, candidate, compatible, upstream, variables = _review_identities(
        review, index
    )
    reason_code, reason, evidence, automatic, state, lifecycle = _review_metadata(
        review, index
    )
    _review_target_key(key, component, kind, candidate)
    generated_views = _review_views(review, index)
    return {
        "review_key": key,
        "component_id": component,
        "component_name": name,
        "review_kind": kind,
        "current_identity": current,
        "candidate_identity": candidate,
        "latest_compatible": compatible,
        "latest_upstream": upstream,
        "canonical_variables": variables,
        "reason_code": reason_code,
        "reason": reason,
        "evidence_urls": evidence,
        "automatic_update_also_available": automatic,
        "state": state,
        **({"lifecycle_evidence": lifecycle} if lifecycle is not None else {}),
        **({"generated_views": generated_views} if generated_views is not None else {}),
    }


def marker(key: str, component: str) -> str:
    return f"<!-- common-version-review:v1 -->\n<!-- common-version-review-key: {key} -->\n<!-- common-version-component: {component} -->"


def issue_title(review: Mapping[str, Any]) -> str:
    current = _display_identity(review["current_identity"])
    candidate = _display_identity(review["candidate_identity"])
    return f"[Manual dependency review] {review['component_name']}: {current} -> {candidate}"


def _display_identity(identity: Mapping[str, str]) -> str:
    return (
        identity.get("version")
        or identity.get("tag")
        or identity.get("series")
        or identity.get("commit")
        or identity.get("asset")
        or identity.get("digest")
        or "unknown"
    )


def issue_body(
    review: Mapping[str, Any], maintenance_run: str = "plan-verified"
) -> str:
    evidence = "\n".join(f"- {url}" for url in review["evidence_urls"])
    variables = (
        ", ".join(f"`{value}`" for value in review["canonical_variables"]) or "(none)"
    )
    status = review.get("state", "active")
    return "\n".join(
        (
            marker(review["review_key"], review["component_id"]),
            "",
            f"Status: `{status}`",
            f"Component: `{review['component_name']}`",
            f"Review type: `{review['review_kind']}`",
            f"Current canonical identity: `{_display_identity(review['current_identity'])}`",
            f"Validated candidate: `{_display_identity(review['candidate_identity'])}`",
            f"Latest compatible: `{review['latest_compatible']}`",
            f"Latest upstream: `{review['latest_upstream']}`",
            f"Reason: {review['reason']}",
            f"Reason code: `{review['reason_code']}`",
            f"Affected common.sh variables: {variables}",
            "Regenerate views: plan-defined generated views",
            "Evidence:",
            evidence,
            f"Last semantic maintenance run: `{maintenance_run}`",
            "",
            "Checklist:",
            "- [ ] Upstream release and migration notes checked",
            "- [ ] Connector compatibility checked",
            "- [ ] Repository, tag, and immutable commit checked",
            "- [ ] Asset and target platform checked",
            "- [ ] Official SHA-256 digest checked",
            "- [ ] Runtime/smoke tests run",
            "- [ ] Generated manifest, lock, and workflow views checked",
            "- [ ] Decision documented",
            "",
            "A comment does not authorize an automatic update.",
        )
    )


class GitHubClient:
    """Small standard-library GitHub REST client; replaceable in tests."""

    def __init__(self, token: str):
        self.token = token

    def request(
        self, method: str, path: str, payload: Optional[Mapping[str, Any]] = None
    ) -> Any:
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            "https://api.github.com" + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        with urlopen(request, timeout=20) as response:
            payload = response.read()
        return json.loads(payload.decode("utf-8")) if payload else None

    def list_issues(self, repository: str) -> list:
        result = []
        for page in range(1, 257):
            query = urlencode({"state": "all", "per_page": 100, "page": page})
            items = self.request("GET", f"/repos/{repository}/issues?{query}")
            if not isinstance(items, list):
                raise PlanError("GitHub returned an invalid issue page")
            result.extend(
                item
                for item in items
                if isinstance(item, dict) and "pull_request" not in item
            )
            if len(items) < 100:
                return result
        raise PlanError("GitHub issue pagination exceeded the safety bound")

    def create_issue(self, repository: str, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", f"/repos/{repository}/issues", payload)

    def update_issue(
        self, repository: str, number: int, payload: Mapping[str, Any]
    ) -> Any:
        return self.request("PATCH", f"/repos/{repository}/issues/{number}", payload)

    def comment(self, repository: str, number: int, body: str) -> Any:
        return self.request(
            "POST", f"/repos/{repository}/issues/{number}/comments", {"body": body}
        )


def _managed_issues(issues: Iterable[Mapping[str, Any]]) -> Dict[str, list]:
    result: Dict[str, list] = {}
    for issue in issues:
        body = issue.get("body") if isinstance(issue, Mapping) else None
        if not isinstance(body, str):
            continue
        key_match = re.fullmatch(
            r".*<!-- common-version-review:v1 -->\n<!-- common-version-review-key: "
            r"([a-z0-9][a-z0-9._:-]{0,159}) -->\n<!-- common-version-component: "
            r"([a-z0-9][a-z0-9._-]{0,63}) -->.*",
            body,
            flags=re.DOTALL,
        )
        if not key_match:
            # An incomplete or contradictory marker is not managed.  In
            # particular, it must never become evidence for inferred closure.
            continue
        key, component = key_match.groups()
        key_component = key.split(":", 1)[0]
        if key_component != component:
            continue
        if not _has_managed_issue_labels(issue, component):
            # A user-created marker is never authority to mutate or close an
            # issue.  Public reporters cannot apply this exact repository
            # label set, so malformed or forged markers are quarantined rather
            # than becoming duplicate-key denial-of-service inputs.
            continue
        result.setdefault(key, []).append(issue)
    duplicates = [key for key, values in result.items() if len(values) != 1]
    if duplicates:
        raise PlanError(
            "duplicate managed issue keys: " + ", ".join(sorted(duplicates))
        )
    return result


def _has_managed_issue_labels(issue: Mapping[str, Any], component: str) -> bool:
    """Accept only issues created under the reconciliation label boundary."""

    labels = issue.get("labels")
    if not isinstance(labels, list):
        return False
    names: list[str] = []
    for label in labels:
        if not isinstance(label, Mapping):
            return False
        name = label.get("name")
        if not isinstance(name, str):
            return False
        names.append(name)
    expected = set(FIXED_LABELS) | {f"component:{component}"}
    return len(names) == len(expected) and set(names) == expected


def _review_kind_from_key(key: str) -> Optional[str]:
    parts = key.split(":", 2)
    if len(parts) != 3 or not COMPONENT_RE.fullmatch(parts[0]):
        return None
    return parts[1] if parts[1] in REVIEW_KINDS else None


def _successful_checked_components(plan: Mapping[str, Any]) -> set[str]:
    """Return components with an observed, non-fatal check result.

    Closure is deliberately stricter than plan validation: the complete
    global inventory is a prerequisite, and every candidate component needs a
    concrete result.  This prevents a partial resolver result from turning
    absence in the plan into issue deletion.
    """
    if plan.get("maintenance_outcome") == "fatal" or not plan.get(
        "global_inventory_complete", False
    ):
        return set()
    fatal = {"unknown", "blocked", "error"}
    results = plan.get("component_results", [])
    return {
        item["component_id"]
        for item in results
        if item.get("component_id") in plan["checked_components"]
        and item.get("status") not in fatal
    }


def _same_content(issue: Mapping[str, Any], review: Mapping[str, Any]) -> bool:
    return issue.get("title") == issue_title(review) and issue.get(
        "body"
    ) == issue_body(review)


def _create_review(
    review: Mapping[str, Any],
    client: Any,
    dry_run: bool,
    repository: str,
    maintenance_run: str,
) -> Dict[str, Any]:
    key = review["review_key"]
    if review.get("state", "active") in {"completed", "superseded", "withdrawn"}:
        return {"action": "noop", "review_key": key}
    payload = {
        "title": issue_title(review),
        "body": issue_body(review, maintenance_run),
        "labels": list(FIXED_LABELS) + [f"component:{review['component_id']}"],
    }
    if dry_run:
        return {"action": "create", "review_key": key, "title": payload["title"]}
    created = client.create_issue(repository, payload)
    return {
        "action": "create",
        "review_key": key,
        "url": created.get("html_url") if isinstance(created, dict) else None,
    }


def _reconcile_active(
    review: Mapping[str, Any],
    issue: Mapping[str, Any],
    client: Any,
    dry_run: bool,
    repository: str,
    maintenance_run: str,
) -> Dict[str, Any]:
    key = review["review_key"]
    number = issue.get("number")
    if issue.get("state") == "closed" and issue.get("state_reason") == "completed":
        if not dry_run:
            client.update_issue(
                repository,
                number,
                {
                    "state": "open",
                    "state_reason": "reopened",
                    "body": issue_body(review, maintenance_run),
                    "title": issue_title(review),
                },
            )
        return {"action": "reopen", "review_key": key, "number": number}
    if _same_content(issue, review):
        return {"action": "noop", "review_key": key, "number": number}
    if not dry_run:
        client.update_issue(
            repository,
            number,
            {"title": issue_title(review), "body": issue_body(review, maintenance_run)},
        )
        client.comment(
            repository,
            number,
            "Validated candidate changed; review plan now targets "
            f"`{_display_identity(review['candidate_identity'])}`.",
        )
    return {"action": "update", "review_key": key, "number": number}


def _reconcile_inactive(
    review: Mapping[str, Any],
    issue: Mapping[str, Any],
    client: Any,
    dry_run: bool,
    repository: str,
) -> Dict[str, Any]:
    key = review["review_key"]
    reason = "completed" if review.get("state") == "completed" else "not_planned"
    number = issue.get("number")
    if issue.get("state") == "closed" and issue.get("state_reason") == reason:
        return {"action": "noop", "review_key": key, "number": number}
    if not dry_run:
        client.comment(
            repository,
            number,
            f"Review marked `{review.get('state')}` by the validated maintenance plan.",
        )
        client.update_issue(
            repository, number, {"state": "closed", "state_reason": reason}
        )
    return {
        "action": "close",
        "review_key": key,
        "number": number,
        "state_reason": reason,
    }


def _reconcile_review(
    review: Mapping[str, Any],
    issue: Mapping[str, Any] | None,
    client: Any,
    dry_run: bool,
    repository: str,
    maintenance_run: str,
) -> Dict[str, Any]:
    if issue is None:
        return _create_review(review, client, dry_run, repository, maintenance_run)
    if review.get("state", "active") == "active":
        return _reconcile_active(
            review, issue, client, dry_run, repository, maintenance_run
        )
    return _reconcile_inactive(review, issue, client, dry_run, repository)


def _reconcile_absent(
    key: str,
    issue: Mapping[str, Any],
    successful: set[str],
    active_kinds: set[tuple[str, str]],
    client: Any,
    dry_run: bool,
    repository: str,
) -> Dict[str, Any] | None:
    parts = key.split(":", 2)
    if len(parts) != 3:
        return None
    component, kind = parts[0], _review_kind_from_key(key)
    if kind is None or component not in successful:
        return None
    reason = "not_planned" if (component, kind) in active_kinds else "completed"
    number = issue.get("number")
    if issue.get("state") == "closed" and issue.get("state_reason") == reason:
        return {"action": "noop", "review_key": key, "number": number}
    if not dry_run:
        client.comment(
            repository,
            number,
            f"Review marked `{reason}` by the validated maintenance plan.",
        )
        client.update_issue(
            repository, number, {"state": "closed", "state_reason": reason}
        )
    return {
        "action": "close",
        "review_key": key,
        "number": number,
        "state_reason": reason,
    }


def reconcile(
    plan: Mapping[str, Any],
    client: Any,
    dry_run: bool = True,
    maintenance_run: str = "plan-verified",
    repository: str = "",
) -> Dict[str, Any]:
    plan = validate_plan(plan)
    if not dry_run and not isinstance(client, GitHubClient):
        required = ("list_issues", "create_issue", "update_issue", "comment")
        if any(not callable(getattr(client, name, None)) for name in required):
            raise PlanError("client does not implement the reconciliation boundary")
    existing = _managed_issues(client.list_issues(repository))
    actions = []
    active_keys = {review["review_key"] for review in plan["manual_reviews"]}
    active_by_component_kind = {
        (review["component_id"], review["review_kind"])
        for review in plan["manual_reviews"]
    }
    for review in plan["manual_reviews"]:
        actions.append(
            _reconcile_review(
                review,
                existing.get(review["review_key"], [None])[0],
                client,
                dry_run,
                repository,
                maintenance_run,
            )
        )

    # Reconcile managed issues which are absent from the active review set.
    # This is intentionally driven by checked component evidence, never by
    # the scope mode alone.  A component filter therefore cannot touch an
    # issue belonging to an unselected runtime component.
    successful_components = _successful_checked_components(plan)
    for key, values in existing.items():
        if key in active_keys:
            continue
        issue = values[0]
        action = _reconcile_absent(
            key,
            issue,
            successful_components,
            active_by_component_kind,
            client,
            dry_run,
            repository,
        )
        if action is not None:
            actions.append(action)
    return {"actions": actions, "count": len(actions), "dry_run": dry_run}


def _apply_allowed(args: argparse.Namespace) -> None:
    if not args.token:
        raise PlanError("--apply requires an explicit --token")
    if not args.trusted_default_branch:
        raise PlanError("--apply requires --trusted-default-branch")
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        raise PlanError("--apply is only allowed in GitHub Actions")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event not in {"schedule", "workflow_dispatch"}:
        raise PlanError("--apply is only allowed for schedule or workflow_dispatch")
    default = os.environ.get("GITHUB_DEFAULT_BRANCH", "master")
    if os.environ.get("GITHUB_REF") != f"refs/heads/{default}":
        raise PlanError("--apply requires the trusted default-branch ref")


def _approved_plan_path(path: str) -> Path:
    """Return a plan path inside the fixed runner/fixture boundary.

    The plan is consumed by both an untrusted validation job and a trusted
    publisher.  O_NOFOLLOW protects the final open, but it does not make an
    arbitrary path safe: callers could otherwise point the CLI at any regular
    file readable by the runner.  Only the fixed workflow artifact in
    RUNNER_TEMP, or the checked-in canonical fixture location, is accepted.
    """
    candidate = Path(path)
    if not candidate.is_absolute() or any(
        part in {"", ".", ".."} for part in candidate.parts
    ):
        raise PlanError(
            "plan path must be an absolute path without traversal components"
        )
    if candidate.name != PLAN_FILENAME:
        raise PlanError(f"plan path must use the fixed filename {PLAN_FILENAME}")

    roots: list[Path] = []
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        runner_root = Path(runner_temp)
        if not runner_root.is_absolute() or any(
            part in {"", ".", ".."} for part in runner_root.parts
        ):
            raise PlanError(
                "RUNNER_TEMP must be an absolute path without traversal components"
            )
        roots.append(runner_root)
    fixture_root = (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "common-version-plans"
    )
    roots.append(fixture_root)

    for root in roots:
        if candidate.parent != root:
            continue
        try:
            root_stat = root.stat()
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        if (
            resolved_root != root
            or not root.is_dir()
            or root_stat.st_uid != os.getuid()
        ):
            continue
        return candidate
    raise PlanError(
        "plan path is outside the approved runner or canonical fixture boundary"
    )


def _read_validated_plan(path: str) -> Dict[str, Any]:
    """Read one bounded plan and apply the canonical schema/digest checks."""
    candidate = _approved_plan_path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_descriptor = os.open(candidate.parent, directory_flags)
    except OSError as error:
        raise PlanError(
            f"cannot open approved plan directory: {candidate.parent}"
        ) from error
    try:
        try:
            descriptor = os.open(PLAN_FILENAME, flags, dir_fd=directory_descriptor)
        except OSError as error:
            raise PlanError(f"cannot open approved plan path: {candidate}") from error
        try:
            stat_result = os.fstat(descriptor)
            candidate_stat = os.stat(
                PLAN_FILENAME, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if not stat.S_ISREG(stat_result.st_mode) or not os.path.samestat(
                stat_result, candidate_stat
            ):
                raise PlanError("plan path must be a regular non-symlink file")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                raw = handle.read(MAX_PLAN_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    finally:
        os.close(directory_descriptor)
    if len(raw) > MAX_PLAN_BYTES:
        raise PlanError("plan exceeds size bound")
    return validate_plan(json.loads(raw.decode("utf-8")))


def _validation_result(plan: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a small stable result suitable for an untrusted resolve job."""
    return {
        "checked_components": list(plan["checked_components"]),
        "generated_view_count": len(plan["generated_views"]),
        "global_inventory_complete": plan.get("global_inventory_complete", False),
        "maintenance_outcome": plan["maintenance_outcome"],
        "manual_review_count": len(plan["manual_reviews"]),
        "mode": "validate-only",
        "plan_sha256": plan["plan_sha256"],
        "safe_update_count": len(plan["safe_updates"]),
        "status": "valid",
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument(
        "--repository", help="owner/name (required for reconciliation modes)"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--validate-only", action="store_true")
    parser.add_argument("--token")
    parser.add_argument("--trusted-default-branch", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            if args.repository or args.token or args.trusted_default_branch:
                raise PlanError(
                    "--validate-only does not accept repository, token, or trusted-branch options"
                )
            plan = _read_validated_plan(args.plan)
            print(
                json.dumps(
                    _validation_result(plan), sort_keys=True, separators=(",", ":")
                )
            )
            return 0
        if not args.repository or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository
        ):
            raise PlanError("a valid repository is required for reconciliation")
        plan = _read_validated_plan(args.plan)
        if args.apply:
            _apply_allowed(args)
        result = reconcile(
            plan,
            GitHubClient(args.token or ""),
            dry_run=args.dry_run,
            repository=args.repository,
            maintenance_run=os.environ.get("GITHUB_RUN_ID", "plan-verified"),
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError) as error:
        print(f"reconciliation failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
