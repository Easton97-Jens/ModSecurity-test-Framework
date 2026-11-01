"""Summarize physical patched captures without assigning I12 oracle results.

Main and neighbor allocations remain separate; configuration-test observers are
excluded from main counts. Missing observations remain missing, never zero/PASS.
"""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def summarize(root):
    receipt = json.loads((root / "receipt.json").read_text())
    native = lines(root / "native.jsonl")
    host = lines(root / "host.jsonl")
    events = lines(root / "events.jsonl")
    starts = [r for r in native if r.get("function") == "runtime_begin_request_stream" and r.get("edge") == "enter"]
    scope = starts[0]["call"] if starts else None
    # A pre-engine mapper rejection can close with zero bytes; then the first
    # allocated scope belongs to the later neighbor. Without an allocation join
    # or a client time boundary, retain unknown instead of assigning that scope.
    if not (receipt.get("main") or {}).get("status_line", "").startswith("HTTP/"):
        scope = None
    main = [r for r in native if scope is not None and r.get("allocation_scope_call") == scope]
    functions = Counter(r["function"] for r in main if r.get("edge") == "enter")
    physical = [r for r in host if scope is not None and r.get("runtime_allocation_scope_call") == scope]
    uri = "/" + receipt["case"]
    matching_events = [r for r in events if r.get("uri") == uri]
    return {
        "case": receipt["case"], "uid": receipt["uid"], "gid": receipt["gid"],
        "reached_stage": receipt.get("reached_stage"), "configtest_returncode": receipt.get("configtest_returncode"),
        "main": receipt.get("main"), "neighbor": receipt.get("neighbor"),
        "backend_main_count": receipt.get("backend_main_count"),
        "backend": receipt.get("backend"), "main_runtime_scope": scope,
        "main_engine_function_counts": dict(functions) if main else None,
        "main_native_mime_selections": [r["native_mime_selection"] for r in main if r.get("native_mime_selection") is not None],
        "main_host_hooks": physical or None,
        "main_physical_events": matching_events,
        "observer_finals": [r for r in native if r.get("function") == "observer" and r.get("edge") == "final"],
        "invalid_native_rows": sum(bool(r.get("invalid")) for r in native) if native else None,
        "launcher_reaped": receipt.get("launcher_reaped"),
        "native_cleanup": receipt.get("native_cleanup"),
        "backend_thread_stopped": receipt.get("backend_thread_stopped"),
        "physical_receipt_sha256": hashlib.sha256((root / "receipt.json").read_bytes()).hexdigest(),
        "event_file_absent": not (root / "events.jsonl").exists(),
        "canonical_oracle_evaluated": False, "full_lifecycle_qualified": False,
        "limits": ["Supplemental capture only; original I12 IDs and independent oracle bindings are not changed.",
                   "Wire chunks and native callback chunks are distinct observations.",
                   "Configuration rejection has no client/backend lifecycle.",
                   "No inferred first technical cause or strict client abort."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_root", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = [summarize(p.parent) for p in sorted((args.capture_root / "cases").glob("*/receipt.json"))]
    i12_paths.create_text(args.output, json.dumps(rows, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cases": len(rows), "output": str(args.output), "canonical_oracle_evaluated": False}))
