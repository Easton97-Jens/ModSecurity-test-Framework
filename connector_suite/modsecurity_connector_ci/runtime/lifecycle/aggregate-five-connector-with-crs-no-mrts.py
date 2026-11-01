#!/usr/bin/env python3
"""Fail closed aggregate for exactly five With-CRS/no-MRTS Parent cells.

The aggregate is a profile-specific evidence boundary.  It never accepts the
similarly named No-CRS profile, never derives identity from artifact directory
names, and reports remaining matrix conditions separately from the five real
selected cell results.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


_THIS = Path(__file__).resolve()
profile = load_source(_THIS.with_name('with-crs-no-mrts-profile.py'))


AGGREGATE_RECORD = "five_connector_with_crs_no_mrts_aggregate"
AGGREGATE_MANIFEST_RECORD = "five_connector_with_crs_no_mrts_aggregate_manifest"
MATRIX_RECORD = "with_crs_no_mrts_current_24_row_disposition"
FACTS_FILE = "functional-facts.json"
RECEIPT_FILE = "profile-cell-receipt.json"
MANIFEST_FILE = "manifest.json"
OUTPUT_NAMES = (
    "aggregate.json",
    "aggregate.md",
    "aggregate.de.md",
    "matrix-24.json",
    "matrix-24.md",
    "matrix-24.de.md",
    MANIFEST_FILE,
)
MATRIX_CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
MATRIX_VARIANTS = (
    ("no_crs_no_mrts", "no-crs", "no-mrts"),
    ("with_crs_no_mrts", "with-crs", "no-mrts"),
    ("no_crs_with_mrts", "no-crs", "with-mrts"),
    ("with_crs_with_mrts", "with-crs", "with-mrts"),
)
CELL_LABEL = "profile cell artifact"
FACTS_LABEL = "functional facts"
RECEIPT_LABEL = "profile cell receipt"
MANIFEST_LABEL = "profile cell manifest"
MANIFEST_BINDING_ERROR = "profile cell manifest does not bind its exact files"


def fail(message: str) -> ValueError:
    return ValueError(message)


def _receipt_fields() -> set[str]:
    return {
        "schema_version",
        "record_type",
        "profile",
        "connector",
        "cell_identity",
        "case_id",
        "executed_test",
        "source_kind",
        "integration_mode",
        "profile_run_id",
        "cell_run_id",
        "cell_run_id_kind",
        "github_run_id",
        "github_run_attempt",
        "artifact_name",
        "parent_sha",
        "base_sha",
        "framework_sha",
        "mrts_sha",
        "crs_commit",
        "crs_rule_file",
        "crs_rule_sha256",
        "functional_facts_sha256",
        "source_files",
        "technical_validation",
        "functional_result",
        "cleanup_status",
        "no_mrts",
    }


def _facts_fields() -> set[str]:
    return {
        "schema_version",
        "record_type",
        "profile",
        "connector",
        "case_id",
        "source_kind",
        "integration_mode",
        "functional_result",
        "allow_control",
        "block",
        "cleanup_status",
        "no_mrts",
        "source_files_sha256",
    }


def _require_exact(value: object, expected: set[str], label: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise fail(f"{label} has missing or unexpected fields")
    return value


def _strict_json_equal(value: object, expected: object) -> bool:
    """Compare parsed canonical JSON without Python bool/int coercion."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not isinstance(value, dict):
            return False
        return set(value) == set(expected) and all(
            _strict_json_equal(value[name], expected[name]) for name in expected
        )
    if isinstance(expected, list):
        if not isinstance(value, list):
            return False
        return len(value) == len(expected) and all(
            _strict_json_equal(actual, wanted)
            for actual, wanted in zip(value, expected, strict=True)
        )
    return value == expected


def _safe_directories(root: Path) -> list[str]:
    names = profile._list_safe(root, "downloaded profile artifacts")
    values: list[str] = []
    descriptor = profile._open_absolute_directory(root, "downloaded profile artifacts")
    try:
        for name in sorted(names):
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
                raise fail("downloaded profile artifact root contains a non-directory")
            profile._directory_is_safe(details, "downloaded profile artifact")
            values.append(name)
    finally:
        os.close(descriptor)
    return values


def _validate_manifest(manifest: Mapping[str, Any], facts_raw: bytes, receipt_raw: bytes) -> None:
    expected_files = [
        {"name": FACTS_FILE, "sha256": hashlib.sha256(facts_raw).hexdigest(), "size_bytes": len(facts_raw)},
        {"name": RECEIPT_FILE, "sha256": hashlib.sha256(receipt_raw).hexdigest(), "size_bytes": len(receipt_raw)},
    ]
    if not _strict_json_equal(manifest["schema_version"], profile.SCHEMA_VERSION):
        raise fail(MANIFEST_BINDING_ERROR)
    if not _strict_json_equal(manifest["record_type"], profile.MANIFEST_RECORD):
        raise fail(MANIFEST_BINDING_ERROR)
    if not _strict_json_equal(manifest["files"], expected_files):
        raise fail(MANIFEST_BINDING_ERROR)


def _validate_receipt(connector: str, receipt: Mapping[str, Any], expected: Mapping[str, str], facts_raw: bytes) -> None:
    for name, wanted in expected.items():
        if not _strict_json_equal(receipt.get(name), wanted):
            raise fail(f"{connector}: receipt {name} does not match the aggregate identity")
    expected_receipt = {
        "schema_version": profile.SCHEMA_VERSION,
        "record_type": profile.PROFILE_RECORD,
        "profile": profile.PROFILE,
        "connector": connector,
        "cell_identity": f"{connector}:with-crs:no-mrts",
        "case_id": profile.CASE_ID,
        "executed_test": profile.CASE_ID,
        "source_kind": profile.SOURCE_KINDS[connector],
        "integration_mode": profile.INTEGRATION_MODES[connector],
        "cell_run_id": f"crs-{expected['github_run_id']}-{expected['github_run_attempt']}-{connector}",
        "cell_run_id_kind": "workflow_cell",
        "artifact_name": f"with-crs-no-mrts-{connector}-{expected['github_run_id']}-{expected['github_run_attempt']}",
        "crs_rule_file": "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "functional_facts_sha256": hashlib.sha256(facts_raw).hexdigest(),
        "technical_validation": "PASS",
        "functional_result": "PASS",
        "cleanup_status": "complete",
    }
    for name, wanted in expected_receipt.items():
        if not _strict_json_equal(receipt.get(name), wanted):
            raise fail(f"{connector}: receipt {name} is invalid")


def _validate_facts(connector: str, facts: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": profile.SCHEMA_VERSION,
        "record_type": profile.FACTS_RECORD,
        "profile": profile.PROFILE,
        "connector": connector,
        "case_id": profile.CASE_ID,
        "source_kind": profile.SOURCE_KINDS[connector],
        "integration_mode": profile.INTEGRATION_MODES[connector],
        "functional_result": "PASS",
        "cleanup_status": "complete",
    }
    for name, wanted in expected.items():
        if not _strict_json_equal(facts.get(name), wanted):
            raise fail(f"{connector}: functional facts {name} are invalid")
    if not _strict_json_equal(facts.get("block"), {"http_status": 403, "action": "deny", "rule_id": profile.RULE_ID}):
        raise fail(f"{connector}: functional facts do not contain the selected CRS block")
    _validate_no_mrts(connector, facts.get("no_mrts"))
    _validate_allow(connector, facts.get("allow_control"))


def _validate_source_files(connector: str, source_files: object, facts: Mapping[str, Any]) -> None:
    if not isinstance(source_files, list) or type(source_files) is not list or not source_files:
        raise fail(f"{connector}: receipt has no source artifact bindings")
    previous = ""
    for item in source_files:
        if not isinstance(item, dict) or type(item) is not dict or set(item) != {"path", "sha256"}:
            raise fail(f"{connector}: source artifact binding is malformed")
        path = item.get("path")
        digest = item.get("sha256")
        if type(path) is not str or type(digest) is not str:
            raise fail(f"{connector}: source artifact binding types are invalid")
        profile._safe_relative_parts(path, "source artifact path")
        profile._require_sha(digest, "source artifact digest", length=64)
        if path <= previous:
            raise fail(f"{connector}: source artifact bindings are not unique and sorted")
        previous = path
    source_digest = facts.get("source_files_sha256")
    if type(source_digest) is not str:
        raise fail(f"{connector}: functional facts source artifact binding digest is invalid")
    profile._require_sha(source_digest, "functional facts source artifact binding digest", length=64)
    if source_digest != hashlib.sha256(profile.canonical_json(source_files)).hexdigest():
        raise fail(f"{connector}: functional facts do not bind the receipt source artifacts")


def _parse_cell(cell_root: Path, expected: Mapping[str, str]) -> tuple[str, dict[str, Any]]:
    names = profile._list_safe(cell_root, CELL_LABEL)
    if names != set(profile.OUTPUT_NAMES):
        raise fail(f"{CELL_LABEL} must contain exactly the canonical three files")
    facts_raw = profile.read_safe(cell_root, FACTS_FILE, FACTS_LABEL)
    receipt_raw = profile.read_safe(cell_root, RECEIPT_FILE, RECEIPT_LABEL)
    manifest_raw = profile.read_safe(cell_root, MANIFEST_FILE, MANIFEST_LABEL)
    facts = profile.parse_json_object(facts_raw, FACTS_LABEL, canonical=True)
    receipt = profile.parse_json_object(receipt_raw, RECEIPT_LABEL, canonical=True)
    manifest = profile.parse_json_object(manifest_raw, MANIFEST_LABEL, canonical=True)
    _require_exact(facts, _facts_fields(), FACTS_LABEL)
    _require_exact(receipt, _receipt_fields(), RECEIPT_LABEL)
    _require_exact(manifest, {"schema_version", "record_type", "files"}, MANIFEST_LABEL)
    _validate_manifest(manifest, facts_raw, receipt_raw)
    connector = receipt.get("connector")
    if connector not in profile.CONNECTORS:
        raise fail("profile receipt contains an unsupported connector")
    connector = str(connector)
    _validate_receipt(connector, receipt, expected, facts_raw)
    _validate_facts(connector, facts)
    if not _strict_json_equal(receipt.get("no_mrts"), facts.get("no_mrts")):
        raise fail(f"{connector}: receipt and functional no-MRTS facts disagree")
    source_files = receipt.get("source_files")
    _validate_source_files(connector, source_files, facts)
    return connector, {
        "receipt": receipt,
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "facts_sha256": hashlib.sha256(facts_raw).hexdigest(),
        "allow_control": facts["allow_control"],
        "block": facts["block"],
        "no_mrts": facts["no_mrts"],
        "allow_observed": facts["allow_control"].get("status") == "observed",
    }


def _validate_no_mrts(connector: str, value: object) -> None:
    if type(value) is not dict:
        raise fail(f"{connector}: no-MRTS disposition is malformed")
    if connector in profile.GENERIC_CONNECTORS:
        flags = {
            "mrts_artifact_used": False,
            "mrts_inventory_loaded": False,
            "mrts_listener_created": False,
            "mrts_process_started": False,
            "mrts_runner_invoked": False,
        }
        if not _strict_json_equal(value, {"status": "runtime_observed", "flags": flags}):
            raise fail(f"{connector}: no-MRTS runtime isolation facts are invalid")
    elif connector == "apache":
        if not _strict_json_equal(value, {"status": "workflow_declared", "workflow_value": "no-mrts"}):
            raise fail(f"{connector}: no-MRTS workflow declaration is invalid")
    elif not _strict_json_equal(value, {"status": "source_declared", "source_value": "no-mrts"}):
        raise fail(f"{connector}: no-MRTS source declaration is invalid")


def _validate_allow(connector: str, value: object) -> None:
    if connector in profile.GENERIC_CONNECTORS:
        if not _strict_json_equal(value, {"status": "observed", "http_status": 200}):
            raise fail(f"{connector}: generic allow control is invalid")
    elif not _strict_json_equal(value, {"status": "not_observed"}):
        raise fail(f"{connector}: non-generic allow disposition is not honest")


def _matrix_rows(cells: Mapping[str, Mapping[str, Any]], identity: Mapping[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for connector in MATRIX_CONNECTORS:
        for profile_name, crs, mrts in MATRIX_VARIANTS:
            selected = connector in cells and profile_name == "with_crs_no_mrts"
            if selected:
                cell = cells[connector]
                rows.append(
                    {
                        "connector": connector,
                        "profile": profile_name,
                        "status": "passed",
                        "execution": "executed",
                        "execution_path": "connector-mode / crs_sqli_anomaly_block / with-crs / no-mrts",
                        "candidate_head": identity["parent_sha"],
                        "base_sha": identity["base_sha"],
                        "observation": {
                            "profile_cell_receipt_sha256": cell["receipt_sha256"],
                            "artifact_name": cell["receipt"]["artifact_name"],
                            "executed_test": cell["receipt"]["executed_test"],
                            "functional_scope": "selected_crs_block_case",
                            "allow_control": cell["allow_control"],
                            "block": cell["block"],
                            "no_mrts": cell["no_mrts"],
                        },
                        "reason": "Fresh exact-head selected with-CRS/no-MRTS cell passed the real CRS block assertion.",
                        "owner": "Parent",
                        "completion_condition": "No additional condition for this selected cell; aggregate remains scoped to this profile.",
                    }
                )
            elif connector in {"envoy", "traefik", "lighttpd"} and mrts == "with-mrts":
                rows.append(
                    {
                        "connector": connector,
                        "profile": profile_name,
                        "status": "blocked",
                        "execution": "not_executed",
                        "execution_path": "not executed: no checked-in executable MRTS route",
                        "candidate_head": identity["parent_sha"],
                        "base_sha": identity["base_sha"],
                        "observation": None,
                        "reason": "No checked-in executable MRTS route exists for this connector/profile; this is not not_applicable.",
                        "owner": "Framework",
                        "completion_condition": "Framework-owned executable route and evidence contract are available and independently validated.",
                    }
                )
            else:
                rows.append(
                    {
                        "connector": connector,
                        "profile": profile_name,
                        "status": "not_run",
                        "execution": "not_executed",
                        "execution_path": "not selected by the authorized five-cell run",
                        "candidate_head": identity["parent_sha"],
                        "base_sha": identity["base_sha"],
                        "observation": None,
                        "reason": "This exact-head route was not selected for the authorized five-cell run; no inference is made from another connector or profile.",
                        "owner": "Parent",
                        "completion_condition": "Run this exact connector/profile with its applicable accepted contract.",
                    }
                )
    return rows


def _counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    values = {"passed": 0, "failed": 0, "blocked": 0, "not_run": 0, "not_applicable": 0}
    for row in rows:
        status = row.get("status")
        if status not in values:
            raise fail("matrix row has an unsupported status")
        values[str(status)] += 1
    if values != {"passed": 5, "failed": 0, "blocked": 6, "not_run": 13, "not_applicable": 0}:
        raise fail("current 24-row disposition does not retain the required honest counts")
    return values


def _render_matrix(matrix: Mapping[str, Any], *, german: bool) -> str:
    title = "Aktuelle 24-Zeilen-CRS/MRTS-Disposition" if german else "Current 24-row CRS/MRTS disposition"
    rows = matrix["rows"]
    candidate_label = "Kandidaten-Head" if german else "Candidate head"
    base_label = "Base"
    headers = (
        "| Connector | Profil | Status | Ausfuehrung | Owner | Grund / Begrenzung | Abschlussbedingung |"
        if german
        else "| Connector | Profile | Status | Execution | Owner | Reason / limitation | Completion condition |"
    )
    lines = [
        f"# {title}",
        "",
        f"{candidate_label}: `{matrix['parent_sha']}`",
        f"{base_label}: `{matrix['base_sha']}`",
        "",
        headers,
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if german:
            if row["status"] == "passed":
                reason = "Die frische exakte With-CRS/No-MRTS-Zelle bestand die reale CRS-Block-Assertion."
                completion = "Keine weitere Bedingung fuer diese begrenzte Zelle; das Aggregat bleibt profilbegrenzt."
            elif row["status"] == "blocked":
                reason = "Keine eingecheckte ausfuehrbare MRTS-Route fuer diesen Connector/dieses Profil; dies ist nicht not_applicable."
                completion = "Framework-eigene ausfuehrbare Route und Evidenzvertrag stehen bereit und sind unabhaengig validiert."
            else:
                reason = "Diese exakte Head-Route wurde im autorisierten Fuenf-Zellen-Lauf nicht ausgewaehlt; es erfolgt keine Inferenz."
                completion = "Dieses exakte Connector/Profil mit seinem anwendbaren akzeptierten Vertrag ausfuehren."
        else:
            reason = row["reason"]
            completion = row["completion_condition"]
        lines.append(
            f"| {row['connector']} | `{row['profile']}` | {row['status']} | {row['execution_path']} | {row['owner']} | {reason} | {completion} |"
        )
    counts = matrix["counts"]
    lines.extend(["", "| passed | failed | blocked | not_run | not_applicable |", "| ---: | ---: | ---: | ---: | ---: |", f"| {counts['passed']} | {counts['failed']} | {counts['blocked']} | {counts['not_run']} | {counts['not_applicable']} |", ""])
    return "\n".join(lines)


def _render_aggregate(summary: Mapping[str, Any], *, german: bool) -> str:
    title = "Fünf-Connector-With-CRS/No-MRTS-Aggregat" if german else "Five-connector With-CRS/no-MRTS aggregate"
    technical = summary["technical_validity"]
    functional = summary["functional_success"]
    matrix = summary["matrix_24_completeness"]
    lines = [
        f"# {title}",
        "",
        f"Candidate head: `{summary['parent_sha']}`",
        f"Base: `{summary['base_sha']}`",
        f"Profile run: `{summary['profile_run_id']}`",
        "",
        f"- {'Technische Gueltigkeit' if german else 'Technical validity'}: `{technical['status']}`",
        f"- {'Ausgewaehltes funktionales Fuenf-Zellen-Ergebnis' if german else 'Selected five-cell functional result'}: `{functional['status']}`",
        f"- {'Aktuelle 24-Zeilen-Disposition' if german else 'Current 24-row disposition'}: `{matrix['status']}` ({matrix['counts']})",
        "",
        "| Connector | Receipt SHA-256 | Allow-control scope |",
        "| --- | --- | --- |",
    ]
    for cell in summary["cells"]:
        if german:
            scope = "beobachtet" if cell["allow_observed"] else "von der ausgewaehlten Quelle nicht beobachtet"
        else:
            scope = "observed" if cell["allow_observed"] else "not_observed_by_selected_source"
        lines.append(f"| {cell['connector']} | `{cell['receipt_sha256']}` | {scope} |")
    lines.extend([
        "",
        (
            "Dieses Artefakt validiert nur die fuenf ausgewaehlten Parent-Zellen. Es behauptet weder einen Framework-weiten Allow-Vertrag noch MRTS-Routenverfuegbarkeit, unabhängige Protected-Host-Attestierung oder Merge-Berechtigung."
            if german
            else "This artifact validates only the five selected Parent cells. It does not claim a Framework-wide allow contract, MRTS-route availability, independent protected-host attestation, or merge eligibility."
        ),
        "",
    ])
    return "\n".join(lines)


def _create_output(root: Path, output: Path) -> tuple[Path, int]:
    root = profile._safe_absolute(root, "aggregate artifact root")
    output = profile._safe_absolute(output, "aggregate output directory")
    if output.parent != root or output.name != "aggregate":
        raise fail("aggregate output must be the fresh aggregate child")
    parent_fd = profile._open_absolute_directory(root, "aggregate artifact root")
    try:
        try:
            os.mkdir("aggregate", 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise fail("aggregate output already exists") from exc
        descriptor = os.open("aggregate", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
                raise fail("aggregate output is not a new private directory")
            os.fsync(parent_fd)
            return output, descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(parent_fd)


def _write_new(directory_fd: int, name: str, data: bytes) -> None:
    if name not in OUTPUT_NAMES or not data:
        raise fail("aggregate output name or value is invalid")
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short aggregate write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def aggregate(args: argparse.Namespace) -> dict[str, Any]:
    identity = {
        "parent_sha": profile._require_sha(args.parent_sha, "candidate head"),
        "base_sha": profile._require_sha(args.base_sha, "base"),
        "profile_run_id": profile._require_token(args.profile_run_id, "profile run ID"),
        "github_run_id": profile._require_token(args.github_run_id, "GitHub run ID", decimal=True),
        "github_run_attempt": profile._require_token(args.github_run_attempt, "GitHub run attempt", decimal=True),
        "framework_sha": profile._require_sha(args.framework_sha, "Framework SHA"),
        "mrts_sha": profile._require_sha(args.mrts_sha, "MRTS SHA"),
        "crs_commit": profile._require_sha(args.crs_commit, "CRS commit"),
        "crs_rule_sha256": profile._require_sha(args.crs_rule_sha256, "CRS rule digest", length=64),
    }
    if identity["parent_sha"] == identity["base_sha"]:
        raise fail("candidate head and base must be distinct")
    expected_profile = f"with-crs-no-mrts-{identity['github_run_id']}-{identity['github_run_attempt']}"
    if identity["profile_run_id"] != expected_profile:
        raise fail("aggregate profile run ID does not match the GitHub invocation")
    root = profile._safe_absolute(args.artifact_root, "downloaded profile artifact root")
    names = _safe_directories(root)
    if len(names) != len(profile.CONNECTORS):
        raise fail("aggregate requires exactly five downloaded profile artifact directories")
    cells: dict[str, dict[str, Any]] = {}
    for name in names:
        connector, cell = _parse_cell(root / name, identity)
        if name != cell["receipt"]["artifact_name"]:
            raise fail("downloaded profile artifact directory does not match its receipt identity")
        if connector in cells:
            raise fail("aggregate contains a duplicate connector receipt")
        cells[connector] = cell
    if tuple(sorted(cells)) != tuple(sorted(profile.CONNECTORS)):
        raise fail("aggregate is missing or contains an unexpected connector")
    rows = _matrix_rows(cells, identity)
    counts = _counts(rows)
    matrix = {
        "schema_version": profile.SCHEMA_VERSION,
        "record_type": MATRIX_RECORD,
        "profile": profile.PROFILE,
        **identity,
        "disposition_complete": True,
        "coverage_complete": False,
        "counts": counts,
        "rows": rows,
    }
    ordered_cells = [
        {"connector": connector, **cells[connector]}
        for connector in profile.CONNECTORS
    ]
    summary = {
        "schema_version": profile.SCHEMA_VERSION,
        "record_type": AGGREGATE_RECORD,
        "profile": profile.PROFILE,
        **identity,
        "technical_validity": {"status": "PASS", "exact_five": True},
        "functional_success": {
            "status": "PASS",
            "scope": "selected_crs_block_case_only",
            "connector_count": len(ordered_cells),
            "allow_controls_observed": [cell["connector"] for cell in ordered_cells if cell["allow_observed"]],
            "allow_controls_not_observed": [cell["connector"] for cell in ordered_cells if not cell["allow_observed"]],
        },
        "matrix_24_completeness": {
            "status": "CURRENT_DISPOSITION_COMPLETE_COVERAGE_INCOMPLETE",
            "counts": counts,
            "disposition_complete": True,
            "coverage_complete": False,
        },
        "remaining_integration_conditions": [
            {
                "finding": "FND-CROSS-0004",
                "status": "blocked",
                "owner": "Framework",
                "condition": "Existing Framework-owned fixture/catalog/schema acceptance and all required resulting hosted rows remain independently required; this Parent aggregate does not close that condition.",
            },
            {
                "finding": "FND-GITHUB-0009",
                "status": "separately_tracked",
                "owner": "Parent",
                "condition": "Hosted PR evidence remains within its documented scope and is not independent protected-host attestation.",
            },
        ],
        "merge_eligible": False,
        "cells": ordered_cells,
        "matrix_24_sha256": hashlib.sha256(profile.canonical_json(matrix)).hexdigest(),
    }
    return {"summary": summary, "matrix": matrix}


def write_outputs(args: argparse.Namespace, result: Mapping[str, Any]) -> None:
    root = profile._safe_absolute(args.artifact_root, "downloaded profile artifact root")
    output, descriptor = _create_output(root, args.output_dir)
    del output
    try:
        summary = result["summary"]
        matrix = result["matrix"]
        data = {
            "aggregate.json": profile.canonical_json(summary),
            "aggregate.md": _render_aggregate(summary, german=False).encode("utf-8"),
            "aggregate.de.md": _render_aggregate(summary, german=True).encode("utf-8"),
            "matrix-24.json": profile.canonical_json(matrix),
            "matrix-24.md": _render_matrix(matrix, german=False).encode("utf-8"),
            "matrix-24.de.md": _render_matrix(matrix, german=True).encode("utf-8"),
        }
        manifest = {
            "schema_version": profile.SCHEMA_VERSION,
            "record_type": AGGREGATE_MANIFEST_RECORD,
            "files": [
                {"name": name, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}
                for name, value in sorted(data.items())
            ],
        }
        data[MANIFEST_FILE] = profile.canonical_json(manifest)
        for name in OUTPUT_NAMES:
            _write_new(descriptor, name, data[name])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--profile-run-id", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--github-run-attempt", required=True)
    parser.add_argument("--framework-sha", required=True)
    parser.add_argument("--mrts-sha", required=True)
    parser.add_argument("--crs-commit", required=True)
    parser.add_argument("--crs-rule-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = aggregate(args)
        write_outputs(args, result)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "profile": profile.PROFILE, "connector_count": 5}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
