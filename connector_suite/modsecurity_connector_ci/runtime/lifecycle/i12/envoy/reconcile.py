#!/usr/bin/env python3
"""Reconcile existing Envoy I12 evidence without performing or promoting host runs."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys


ROOT = connector_root()

import modsecurity_connector_ci.lib.i12_path_safety as paths

CURRENT = load_source(source_path('ci/evidence/reports/generate-pr382-i12-current-report.py', root=ROOT))
ORACLES = CURRENT.ORACLES
ROUTES = {
    "envoy-ext-proc": (117, 51),
    "envoy-ext-authz-request": (94, 40),
    "envoy-ext-authz-response-companion": (73, 34),
}


def validate(ledger, oracles):
    """Use shared immutable-contract and physical-packet validators read-only."""
    references = oracles.get("input_evidence", [])
    if len(references) != 3:
        raise ValueError("Three original physical oracle inputs are required")
    inputs = [json.loads(Path(ORACLES.verify_reference(ref)["path"]).read_text())
              for ref in references]
    # Rebuilding also checks original596 membership/order, independent sources,
    # per-ID effective oracles, retests and every oracle summary counter.
    expected = ORACLES.reconcile(inputs[0], inputs[1], inputs[2]["records"])
    if any(oracles.get(key) != value for key, value in expected.items()):
        raise ValueError("Oracle inventory, dispositions or summary differ from physical inputs")
    CURRENT.validate(ledger, oracles, {"i12_status": "I12_PARTIAL"})
    for route, (count, original_oracles) in ROUTES.items():
        members = [row for row in ledger["rows"] if row["leg_id"] == route]
        inventory = [row for row in oracles["oracle_matrix"] if row["leg_id"] == route]
        if len(members) != count or len(inventory) != original_oracles:
            raise ValueError("Original Envoy route or oracle inventory changed")


def physical_references(value):
    """Retain distinct physical references, preserving producer roles."""
    found = {}

    def visit(item):
        if isinstance(item, dict):
            if "path" in item and "sha256" in item:
                checked = ORACLES.verify_reference(item)
                found[(checked["path"], checked.get("role"), checked.get("kind"))] = checked
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return list(found.values())


def reconciled_row(row):
    review = row["oracle_reconciliation"]
    packet = row["current_lifecycle_packet"]
    original = row["selected_requirement"]["expected_oracle"]
    is_original_oracle = bool(original.get("unresolved_expected_value_reason"))
    resolved = bool(review and review["resolved"])
    residual = []
    if row["qualification_scope"] is None:
        residual.append("full_host_lifecycle_not_qualified")
    elif row["qualification_scope"] == "historical_configuration_only":
        residual.append("configuration_only_requires_host_lifecycle")
    if is_original_oracle and not resolved:
        residual.append("original_oracle_unresolved")
    if packet:
        residual.extend("unknown_observation:" + field for field in packet["unknown_fields"])
    return {
        "run_scoped_case_id": row["run_scoped_case_id"],
        "leg_id": row["leg_id"],
        "status": row["status"],
        "execution_observed": row["execution_observed"],
        "qualification_scope": row["qualification_scope"],
        "qualified_host_lifecycle_pass": row["qualified_host_lifecycle_pass"],
        "original_oracle_member": is_original_oracle,
        "original_oracle": copy.deepcopy(original),
        "oracle_review": copy.deepcopy(review),
        "existing_host_packet": copy.deepcopy(packet["receipt"]) if packet else None,
        "unknown_observations": copy.deepcopy(packet["unknown_fields"]) if packet else None,
        "physical_evidence": physical_references({"packet": packet, "review": review}),
        "residual": residual,
    }


def reconcile(ledger, oracles):
    """Return all284 exact IDs; source confirmation never supplies a host PASS."""
    validate(ledger, oracles)
    result = {
        "schema_version": 1,
        "evidence_scope": "revalidated_existing_evidence",
        "new_host_runs": 0,
        "original_ordered_id_sha256": ledger["original_ordered_id_sha256"],
        "original_selected_contract_sha256": ledger["original_selected_contract_sha256"],
        "routes": {},
        "rows": [],
    }
    for row in ledger["rows"]:
        if row["leg_id"] not in ROUTES:
            continue
        result["rows"].append(reconciled_row(row))
    for route in ROUTES:
        rows = [row for row in result["rows"] if row["leg_id"] == route]
        original = [row for row in rows if row["original_oracle_member"]]
        resolved = [row for row in original if row["oracle_review"]["resolved"]]
        result["routes"][route] = {
            "original_ids": len(rows),
            "existing_lifecycle_pass": sum(row["qualified_host_lifecycle_pass"] for row in rows),
            "configuration_only_pass": sum(row["qualification_scope"] == "historical_configuration_only" for row in rows),
            "unqualified_ids": sum(row["qualification_scope"] is None for row in rows),
            "original_oracles": len(original),
            "resolved_original_oracles": len(resolved),
            "open_original_oracles": len(original) - len(resolved),
            "existing_pass_ids": [row["run_scoped_case_id"] for row in rows if row["qualified_host_lifecycle_pass"]],
            "open_oracle_ids": [row["run_scoped_case_id"] for row in original if not row["oracle_review"]["resolved"]],
            "residual_ids": [row["run_scoped_case_id"] for row in rows if row["residual"]],
        }
    result["summary"] = {
        key: sum(route[key] for route in result["routes"].values())
        for key in ("original_ids", "existing_lifecycle_pass", "configuration_only_pass",
                    "unqualified_ids", "original_oracles", "resolved_original_oracles",
                    "open_original_oracles")
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ledger", "oracles", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    refs = {name: ORACLES.reference(getattr(args, name).absolute())
            for name in ("ledger", "oracles")}
    inputs = {name: json.loads(Path(ref["path"]).read_text()) for name, ref in refs.items()}
    output = reconcile(inputs["ledger"], inputs["oracles"])
    output["input_evidence"] = refs
    # Exclusive creation protects both the original inputs and prior evidence.
    with paths.new_text(args.output) as stream:
        json.dump(output, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
