#!/usr/bin/env python3
"""Extract the inherited lighttpd I12 checkpoint without qualifying new evidence.

Input originals remain external and SHA-bound. Compact records retain exact
selected contracts; full observation packets are recoverable by ID and row hash.
Supplemental references never change an inherited status or resolve an oracle.
"""
import argparse
import hashlib
import json
import os
import stat
from collections import Counter
from pathlib import Path


ROUTES = {
    "lighttpd-stock-sidecar": (153, 51),
    "lighttpd-patched-native": (116, 52),
    "lighttpd-stock-native-control": (78, 23),
}
DIAGNOSTIC = "lighttpd-stock-native-control"
STATUS_FIELDS = (
    "status", "execution_observed", "execution_missing_reason",
    "qualified_full_case_pass", "qualified_host_lifecycle_pass",
    "qualification_scope", "historical_status", "historical_execution_observed",
    "product_failure_observed", "product_failure_missing_reason",
    "binding_missing_reason",
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def physical_path(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError(f"Expected physical path without symlink components: {path}")
    return path


def snapshot(path):
    path = physical_path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"Expected unshared physical regular file: {path}")
        raw = stream.read()
        after = os.fstat(stream.fileno())
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after) or identity(after) != identity(path.stat()):
        raise ValueError(f"Input changed during read: {path}")
    return raw, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                 "bytes": len(raw)}


def reference(path):
    return snapshot(path)[1]


def write_files(output_dir, files):
    output_dir = physical_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    targets = [(output_dir / name, value) for name, value in files.items()]
    for target, _ in targets:
        if target.exists() or target.is_symlink():
            raise ValueError(f"Refusing existing output: {target}")
    for target, value in targets:
        with target.open("x") as stream:
            stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def index_rows(rows, label):
    index = {}
    for row in rows:
        case_id = row["run_scoped_case_id"]
        if case_id in index:
            raise ValueError(f"Duplicate {label} ID: {case_id}")
        if case_id.split("::")[1] != row["leg_id"]:
            raise ValueError(f"Wrong route binding: {case_id}")
        index[case_id] = row
    return index


def compact_oracles(original_oracles, indexed):
    source_bindings = {}
    compact_oracles = []
    for oracle in original_oracles:
        case_id = oracle["run_scoped_case_id"]
        if case_id not in indexed or not oracle["original_596_member"]:
            raise ValueError(f"Wrong original oracle membership: {case_id}")
        if oracle["original_selected_requirement"] != indexed[case_id]["selected_requirement"]:
            raise ValueError(f"Changed original requirement: {case_id}")
        binding = {key: oracle[key] for key in
                   ("original_source_revision", "original_source_hashes")}
        binding_id = digest(binding)
        source_bindings[binding_id] = binding
        compact = {k: v for k, v in oracle.items() if k not in binding}
        compact["original_source_binding_sha256"] = binding_id
        compact["original_row_sha256"] = digest(oracle)
        compact_oracles.append(compact)
    return compact_oracles, source_bindings


def compact_cases(rows, route):
    compact_rows = []
    for row in rows:
        if row["required_leg"] != (route != DIAGNOSTIC):
            raise ValueError(f"Diagnostic/required route confusion: {route}")
        if route == DIAGNOSTIC and row.get("qualification_scope") == "full_host_lifecycle":
            raise ValueError("Stock-native diagnostic cannot inherit body-streaming lifecycle qualification")
        compact_rows.append({
            "run_scoped_case_id": row["run_scoped_case_id"],
            "leg_id": route, "required_leg": row["required_leg"],
            "selected_requirement": row["selected_requirement"],
            **{field: row.get(field) for field in STATUS_FIELDS},
            "original_row_sha256": digest(row),
        })
    return compact_rows


def route_summary(rows, original_oracles, route):
    lifecycle = sum(r.get("qualified_host_lifecycle_pass") is True for r in rows)
    config = sum(r["status"] == "PASS" and r.get("qualification_scope") !=
                 "full_host_lifecycle" for r in rows)
    return {
        "original_ids": len(rows),
        "required_leg": route != DIAGNOSTIC,
        "execution_observed": sum(r["execution_observed"] is True for r in rows),
        "full_lifecycle_pass": lifecycle,
        "configuration_only_pass": config,
        "unqualified_ids": sum(r["status"] != "PASS" for r in rows),
        "original_oracles": len(original_oracles),
        "resolved_original_oracles": sum(r["resolved"] is True for r in original_oracles),
        "unresolved_original_oracles": sum(r["resolved"] is not True for r in original_oracles),
        "oracle_categories": dict(Counter(r["category"] for r in original_oracles)),
    }


def reconcile(ledger, oracles, sources, supplemental=None):
    """Return six route files and summary; never mutate either input."""
    supplemental = supplemental or {}
    if set(supplemental) - ROUTES.keys():
        raise ValueError("Supplemental evidence names a non-lighttpd route")
    index_rows(ledger["rows"], "ledger")
    index_rows(oracles["oracle_matrix"], "oracle")
    for field in ("original_ordered_id_sha256", "original_selected_contract_sha256"):
        if ledger[field] != oracles[field]:
            raise ValueError(f"Different original inventory: {field}")
    files = {}
    summaries = {}
    for route, (case_count, oracle_count) in ROUTES.items():
        rows = [r for r in ledger["rows"] if r["leg_id"] == route]
        original_oracles = [r for r in oracles["oracle_matrix"] if r["leg_id"] == route]
        if len(rows) != case_count or len(original_oracles) != oracle_count:
            raise ValueError(f"Wrong original membership count for {route}")
        compact_oracle_rows, source_bindings = compact_oracles(
            original_oracles, {r["run_scoped_case_id"]: r for r in rows})
        compact_rows = compact_cases(rows, route)
        summaries[route] = route_summary(rows, original_oracles, route)
        common = {"schema": "lighttpd-i12-inherited-ledger-v1", "route": route,
                  "qualification_performed_by_exporter": False,
                  "new_evidence_refs": supplemental.get(route, []),
                  "new_evidence_changes_inherited_status": False,
                  "input_sources": sources, "summary": summaries[route]}
        files[f"{route}-cases.json"] = {**common, "rows": compact_rows}
        files[f"{route}-oracles.json"] = {**common,
            "original_source_bindings": source_bindings, "rows": compact_oracle_rows}
    files["summary.json"] = {"schema": "lighttpd-i12-inherited-summary-v1",
        "qualification_performed_by_exporter": False, "input_sources": sources,
        "routes": summaries}
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--reconciliation", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--new-evidence", action="append", default=[], metavar="ROUTE=PATH")
    args = parser.parse_args()
    ledger_raw, ledger_ref = snapshot(args.ledger)
    oracle_raw, oracle_ref = snapshot(args.reconciliation)
    sources = {"ledger": ledger_ref, "reconciliation": oracle_ref}
    supplemental = {}
    for item in args.new_evidence:
        route, path = item.split("=", 1)
        supplemental.setdefault(route, []).append(reference(path))
    files = reconcile(json.loads(ledger_raw), json.loads(oracle_raw), sources, supplemental)
    write_files(args.output_dir, files)
    print(json.dumps(files["summary.json"]["routes"], indent=2))


if __name__ == "__main__":
    main()
