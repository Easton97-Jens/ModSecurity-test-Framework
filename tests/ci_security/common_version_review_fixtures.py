"""Shared production-shaped plan records for review-reconciler tests."""

from __future__ import annotations


GLOBAL_COMPONENT_DEFINITIONS = (
    ("go-ftw", "go-ftw", "GO_FTW_RELEASE_TAG"),
    ("albedo", "albedo", "ALBEDO_RELEASE_TAG"),
    ("python", "python", "CI_CANONICAL_PYTHON_VERSION"),
    ("pyyaml", "pyyaml", "CI_CANONICAL_PYYAML_VERSION"),
    ("node", "node", "CI_CANONICAL_NODE_VERSION"),
    ("github-action-checkout", "github-actions", "CI_ACTION_CHECKOUT_VERSION"),
    (
        "ci-tool-shellcheck",
        "ci-security-tools",
        "CI_SECURITY_TOOL_SHELLCHECK_VERSION",
    ),
    (
        "ci-osv-compatibility",
        "ci-security-tools",
        "CI_OSV_LEGACY_BASE_VERSION",
    ),
    (
        "canonical-ci-coverage",
        "ci-security-tools",
        "CI_CANONICAL_PYTHON_VERSION",
    ),
)
RUNTIME_COMPONENT_DEFINITIONS = (("lighttpd", "runtime-source", "LIGHTTPD_VERSION"),)
COMPONENT_DEFINITIONS = (
    *GLOBAL_COMPONENT_DEFINITIONS,
    *RUNTIME_COMPONENT_DEFINITIONS,
)
GLOBAL_COMPONENT_IDS = [
    component_id for component_id, _scope, _variable in GLOBAL_COMPONENT_DEFINITIONS
]


def make_component_result(
    component_id: str,
    scope: str,
    variable: str,
    status: str = "current",
) -> dict[str, object]:
    optional_summary = {
        "current": "1.0.0",
        "latest_compatible": "1.0.0",
        "latest_upstream": "1.0.0",
        "source": f"https://example.invalid/{component_id}",
    }
    if component_id == "ci-osv-compatibility":
        optional_summary["source"] = ""
    elif component_id == "canonical-ci-coverage":
        optional_summary = dict.fromkeys(optional_summary, "")
    return {
        "component_id": component_id,
        "component_name": component_id,
        "scope": scope,
        "status": status,
        "message": "checked",
        "canonical_variables": [variable],
        **optional_summary,
        "updates": [],
        "details": {},
    }


def make_component_results(
    component_ids: list[str] | None = None,
    statuses: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    selected = set(component_ids) if component_ids is not None else None
    statuses = statuses or {}
    return [
        make_component_result(
            component_id,
            scope,
            variable,
            statuses.get(component_id, "current"),
        )
        for component_id, scope, variable in COMPONENT_DEFINITIONS
        if selected is None or component_id in selected
    ]
