#!/usr/bin/env python3
"""Bind supported diagnostic requests to immutable catalog/YAML expectations."""
import argparse
import hashlib
import json
from pathlib import Path

import yaml

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def source_ref(path, revision):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "revision": revision}


def resolve_case(name, cases):
    visited = set()
    while True:
        if name in visited:
            raise ValueError("Catalog reuse cycle")
        visited.add(name)
        case = cases[name]
        target = case.get("request", {}).get("reuses") or case.get("deprecated_alias_for")
        if not target:
            return case
        name = target


def sequence_plan(case, cases, framework, framework_sha):
    sequence = case.get("request", {}).get("sequence")
    if not sequence or case["case_id"] not in ("single_request_cleanup", "multiple_sequential_requests", "clean_shutdown"):
        return None
    requests, statuses, references = [], [], []
    for name in sequence:
        if name == "shutdown":
            continue
        selected = resolve_case(name, cases)
        runner = selected["runner_case"]
        if not runner.startswith("tests/"):
            runner = "tests/cases/no-crs-baseline/" + runner
        path = framework / runner
        request = yaml.safe_load(path.read_text())["request"]
        headers = request.get("headers", {})
        headers = list(headers.items()) if isinstance(headers, dict) else [(h["name"], h["value"]) for h in headers]
        requests.append({"method": request.get("method", "GET"), "path": request["path"], "headers": headers})
        statuses.append(selected["expected_status"])
        references.append(source_ref(path, framework_sha))
    return {"request": requests[-1], "sequence_prefix": requests[:-1], "expected_sequence_statuses": statuses,
            "declared_shutdown": sequence[-1] == "shutdown", "original_sequence": sequence,
            "independent_sequence_sources": references}


def request_headers(request):
    headers = request.get("headers", [])
    if isinstance(headers, dict):
        return list(headers.items())
    return [(item["name"], item["value"]) for item in headers]


def plan_case(case_id, cases, contract, framework, framework_sha, catalog_file, rules_file, baseline_rules):
    case = resolve_case(case_id, cases)
    runner = case.get("runner_case") or contract.get("runner_case")
    if runner and not runner.startswith("tests/"):
        runner = "tests/cases/no-crs-baseline/" + runner
    yaml_case = yaml.safe_load((framework / runner).read_text()) if runner else {}
    request = yaml_case.get("request") or case.get("request")
    sequence = sequence_plan(case, cases, framework, framework_sha)
    if sequence:
        return {"case_id": case_id, "original_selected_requirement": contract,
            "original_expected_oracle": contract["expected_oracle"], "rules": baseline_rules,
            "backend_marker": None, "independent_sources": [source_ref(catalog_file, framework_sha),
                source_ref(rules_file, framework_sha), *sequence["independent_sequence_sources"]], **sequence}
    if not request or "path" not in request:
        return {"case_id": case_id, "reason": "Original catalog is not a concrete single-request HTTP fixture."}
    headers = request_headers(request)
    refs = [source_ref(catalog_file, framework_sha), source_ref(rules_file, framework_sha)]
    if runner:
        refs.append(source_ref(framework / runner, framework_sha))
    return {"case_id": case_id, "original_selected_requirement": contract,
        "canonical_request_case_id": case["case_id"], "original_expected_oracle": contract["expected_oracle"],
        "request": {"method": request.get("method", "GET"), "path": request["path"], "headers": headers},
        "rules": baseline_rules + "\n" + yaml_case.get("rules", ""),
        "backend_marker": "block" if contract["expected_oracle"].get("phase") == 3 else None,
        "independent_sources": refs, "reused_request_is_distinct_execution": True}


def plan(framework, original, framework_sha, selected=None):
    catalog_file = framework / "tests/cases/no-crs-baseline/catalog.json"
    catalog = json.loads(catalog_file.read_text())
    cases = {case["case_id"]: case for case in catalog["cases"]}
    rules_file = framework / catalog["ruleset"]["path"]
    baseline_rules = rules_file.read_text()
    planned, unavailable = [], []
    for row in json.loads(original.read_text())["rows"]:
        contract = row["selected_requirement"]
        case_id = contract["case_id"]
        if selected and case_id not in selected:
            continue
        if case_id not in cases:
            unavailable.append({"case_id": case_id, "reason": "Original named diagnostic needs its own explicit fixture/oracle resolution."})
            continue
        candidate = plan_case(case_id, cases, contract, framework, framework_sha, catalog_file, rules_file, baseline_rules)
        (planned if "request" in candidate else unavailable).append(candidate)
    return {"route": "lighttpd-stock-native-control", "cases": planned, "unavailable": unavailable}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", required=True, type=Path)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--framework-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    result = plan(args.framework, args.original, args.framework_sha, args.case)
    with i12_paths.new_text(args.output) as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({"cases": len(result["cases"]), "unavailable": len(result["unavailable"])}))


if __name__ == "__main__":
    main()
