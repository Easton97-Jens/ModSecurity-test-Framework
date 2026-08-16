"""Regression coverage for mandatory CI inventory and URL tuple ownership."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_common_versions", ROOT / "ci/tools/check-common-versions.py"
)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def _entries(*names: str):
    return {name: object() for name in names}


def test_ci_inventory_discovers_longest_fields_and_rejects_incomplete_groups():
    names, errors = CHECKER.canonical_ci_group_inventory(
        _entries(
            "CI_ACTION_FOO_REPOSITORY",
            "CI_ACTION_FOO_VERSION",
            "CI_ACTION_FOO_COMMIT",
            "CI_SECURITY_TOOL_BAR_REPOSITORY",
            "CI_SECURITY_TOOL_BAR_VERSION",
            "CI_SECURITY_TOOL_BAR_COMMIT",
            "CI_SECURITY_TOOL_BAR_ASSET_NAME",
            "CI_SECURITY_TOOL_BAR_SHA256",
            "CI_CANONICAL_PYYAML_VERSION",
            "CI_CANONICAL_PYYAML_SHA256",
            "CI_CANONICAL_PYYAML_ARTIFACT",
            "CI_CANONICAL_PYYAML_PLATFORM",
            "CI_CANONICAL_PYTHON_VERSION",
        )
    )
    assert "CI_SECURITY_TOOL_BAR_ASSET_NAME" in names
    assert errors == []


def test_ci_inventory_rejects_obsolete_pyyaml_wheel():
    _, errors = CHECKER.canonical_ci_group_inventory(
        _entries(
            "CI_CANONICAL_PYYAML_VERSION",
            "CI_CANONICAL_PYYAML_SHA256",
            "CI_CANONICAL_PYYAML_WHEEL",
            "CI_CANONICAL_PYYAML_PLATFORM",
        )
    )
    assert any("unsupported canonical variable" in error and "WHEEL" in error for error in errors)


def test_component_selection_always_keeps_global_descriptors():
    selected = CHECKER.canonical_component_selection(["lighttpd"])
    assert selected == ("lighttpd",)
    mandatory = {"go-ftw", "Albedo", "Canonical CI pins"}
    selected_names = set(selected) | mandatory
    assert mandatory <= selected_names


def test_official_roots_are_the_current_single_slash_contract():
    lighttpd = CHECKER.COMPONENT_DEFINITION_BY_NAME["lighttpd"]
    haproxy = CHECKER.COMPONENT_DEFINITION_BY_NAME["HAProxy"]
    assert lighttpd.authorized_hosts == ("download.lighttpd.net",)
    assert haproxy.authorized_hosts == ("www.haproxy.org",)
    assert "HAProxy HTX" in CHECKER.COMPONENT_DEFINITION_BY_NAME
