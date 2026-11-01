#!/usr/bin/env python3
"""Inventory physical layers for all original diagnostic IDs without promotion."""
from modsecurity_test_framework.connector_context import load_source
import argparse
import importlib.util
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths

ROUTE = "lighttpd-stock-native-control"


def adapter():
    module = load_source(Path(__file__).with_name('qualification.py'))
    return module


def indexed(paths, q):
    result = {}
    for path in sorted(paths):
        data = json.loads(path.read_text())
        case_id = data.get("run_scoped_case_id")
        if case_id and case_id.startswith("I12::" + ROUTE + "::"):
            result.setdefault(case_id, []).append({"reference": q.reference(path), "data": data})
    return result


def parser_index(run, q):
    result = {}
    for path in sorted((run / "isolation").glob("attempt-*/data/configcontrols/receipt.json")):
        data = json.loads(path.read_text())
        for probe in data["configuration_probes"]:
            case_id = "I12::" + ROUTE + "::" + probe["case_id"]
            physical = path.parent / probe["case_id"] / "parser-process.json"
            result.setdefault(case_id, []).append({"summary": q.reference(path), "case_id": probe["case_id"],
                "actual_exit": probe["exitcode"], "scope": "configuration_parser_only",
                "physical_process": q.reference(physical) if physical.is_file() else None,
                "missing_physical_process_reason": None if physical.is_file() else "Historical summary has no independently bound per-process receipt."})
    return result


def producer_receipts(refs, q):
    receipts, errors = [], []
    for ref in refs:
        if ref.get("role") not in ("client_process", "backend_process", "parser_process", "cleanup_observer", "native_api"):
            continue
        try:
            q.ORACLES.verify_reference(ref)
        except (ValueError, OSError) as error:
            errors.append({"reference": ref, "error": str(error)})
        else:
            if ref not in receipts:
                receipts.append(ref)
    return receipts, errors


def observations(proposals, q):
    output = []
    for item in proposals:
        packet = item["data"]
        refs = list(packet.get("measurement_evidence", []))
        for value in packet.get("observations", {}).values():
            refs.extend(value.get("evidence", []))
        receipts, errors = producer_receipts(refs, q)
        oracle_path = Path(item["reference"]["path"].replace("-packet-proposal.json", "-oracle-proposal.json"))
        output.append({"packet_proposal": item["reference"], "oracle_proposal": q.reference(oracle_path),
                       "execution_kind": packet["execution_kind"],
                       "execution_observed": packet["execution_observed"],
                       "worker_predicate": packet.get("outcome"), "worker_predicate_is_qualification": False,
                       "actual_producer_refs": receipts, "invalid_producer_refs": errors})
    return output


def physical_capture(item, q):
    receipt = item["data"]
    directory = Path(item["reference"]["path"]).parent
    name = receipt["case_id"]
    witnesses = {}
    candidates = {"client_process": directory / (name + ".process.json"),
        "backend_process": directory / "backend.jsonl", "native_api": directory / "native.jsonl",
        "host_callback": directory / "host.jsonl", "cleanup_observer": directory / "capture.json",
        "actual_host_process": directory / "host-identity.json"}
    for role, path in candidates.items():
        witnesses[role] = (q.reference(path, role) if path.is_file() else
            {"path": str(path), "missing_reason": "This invocation produced no such physical receipt; no producer is inferred."})
    return {"reference": item["reference"],
        "layer": "host_http" if receipt.get("execution_observed") is True else "startup_or_incomplete_capture",
        "execution_observed": receipt.get("execution_observed", False),
        "client_waited_exit": receipt.get("main", {}).get("waited_exit"),
        "client_waited_signal": receipt.get("main", {}).get("waited_signal"),
        "actual_http_status": receipt.get("main", {}).get("status"),
        "actual_startup_failure": receipt.get("actual_startup_failure"),
        "actual_actor_process_status": receipt.get("actors_cleanup"),
        "actual_host_cleanup": receipt.get("actual_host_cleanup"),
        "listeners_after_cleanup": receipt.get("listeners_after_cleanup"),
        "independent_physical_witnesses": witnesses}


def inventory(args):
    q = adapter()
    original = json.loads(args.baseline.read_text())
    original_oracles = args.baseline.with_name(args.baseline.name.replace("-cases.json", "-oracles.json"))
    oracle_ids = {row["run_scoped_case_id"] for row in json.loads(original_oracles.read_text())["rows"]}
    if len(oracle_ids) != 23:
        raise ValueError("Diagnostic original oracle inventory must contain 23 unique IDs")
    proposals = indexed((args.run / "diagnostic").glob("proposals-*/*-packet-proposal.json"), q)
    qualified = indexed((args.run / "qualified").glob("diagnostic*/*/qualification.json"), q)
    captures = indexed((args.run / "isolation").glob("attempt-*/data/diagnostic/*/capture.json"), q)
    parsers = parser_index(args.run, q)
    catalog = {row["case_id"]: row for row in json.loads(args.catalog.read_text())["cases"]}
    rows = []
    for inherited in original["rows"]:
        case_id = inherited["run_scoped_case_id"]
        selected = inherited["selected_requirement"]
        case = selected["case_id"]
        proposal_rows = observations(proposals.get(case_id, []), q)
        qualification_rows = qualified.get(case_id, [])
        physical = [physical_capture(item, q) for item in captures.get(case_id, [])]
        row = {"run_scoped_case_id": case_id, "original_row_sha256": inherited["original_row_sha256"],
               "original_oracle_inventory_member": case_id in oracle_ids,
               "original_selected_requirement": selected, "original_status": inherited.get("status"),
               "source_catalog_request": catalog.get(case, {}).get("request"),
               "source_required_capabilities": catalog.get(case, {}).get("required_capabilities"),
               "capture_refs": physical, "parser_receipts": parsers.get(case_id, []),
               "proposals": proposal_rows,
               "root_qualification_refs": [item["reference"] for item in qualification_rows],
               "independent_root_statuses": [item["data"].get("status") for item in qualification_rows],
               "unsupported_capability_claimed": False}
        if qualification_rows:
            row["coverage_layer"] = "root_qualification_exists_requires_current_shared_revalidation"
            row["remaining_evidence"] = []
        elif proposal_rows:
            row["coverage_layer"] = "physical_proposal_pending_independent_root_review"
            row["remaining_evidence"] = ["Exact packet/oracle Root review and current shared qualification result."]
        else:
            row["coverage_layer"] = "physical_layer_only" if physical or parsers.get(case_id) else "not_executed"
            row["remaining_evidence"] = selected.get("mandatory_missing_observations", [])
            row["remaining_fixture_contract"] = (catalog.get(case, {}).get("request") or
                {"original_requirement_mapping": selected.get("requirement_mapping"),
                 "reason": "Original named diagnostic has no separately executed and qualified fixture in this inventory."})
        rows.append(row)
    if len(rows) != 78 or len({row["run_scoped_case_id"] for row in rows}) != 78:
        raise ValueError("Diagnostic inventory must preserve all 78 unique original IDs")
    return {"route": ROUTE, "status_is_qualification": False,
            "original_baseline": q.reference(args.baseline), "original_oracles": q.reference(original_oracles),
            "catalog_source": q.reference(args.catalog),
            "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "catalog", "run", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() != args.output.absolute() or args.output.exists():
        raise ValueError("Inventory output must be a fresh physical file")
    with i12_paths.new_text(args.output) as stream:
        json.dump(inventory(args), stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
