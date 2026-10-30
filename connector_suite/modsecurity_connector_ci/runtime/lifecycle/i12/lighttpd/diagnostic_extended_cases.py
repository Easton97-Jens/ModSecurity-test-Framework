#!/usr/bin/env python3
"""Predeclare remaining diagnostic wire, mapping, and lifecycle fixtures."""
import argparse
import hashlib
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


DIAGNOSTIC_PREFIX = "/diagnostic/"


def reference(path, revision):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "revision": revision}


def wire(path, headers=(), *, close=True, method="GET", body=b""):
    fields = [("Host", "localhost"), *headers, ("Connection", "close" if close else "keep-alive")]
    raw = (f"{method} {path} HTTP/1.1\r\n" + "".join(name + ": " + value + "\r\n" for name, value in fields) + "\r\n").encode() + body
    return {"path": path, "wire_hex": raw.hex()}


def generate(args):
    originals = {row["selected_requirement"]["case_id"]: row["selected_requirement"]
                 for row in json.loads(args.original.read_text())["rows"]}
    rules_path = args.framework / "tests/rules/no-crs-baseline.conf"
    catalog_path = args.framework / "tests/cases/no-crs-baseline/catalog.json"
    rules = rules_path.read_text()
    sources = [reference(catalog_path, args.framework_sha), reference(rules_path, args.framework_sha)]
    planned = []

    def add(name, request, **extra):
        original = originals[name]
        planned.append({"case_id": name, "original_selected_requirement": original,
            "original_expected_oracle": original["expected_oracle"], "request": request,
            "rules": rules, "backend_marker": None, "independent_sources": sources, **extra})

    malformed = {
        "invalid_content_length": [("Content-Length", "invalid")],
        "conflicting_content_length": [("Content-Length", "0"), ("Content-Length", "1")],
        "duplicate_transfer_encoding": [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")],
        "content_length_overflow": [("Content-Length", "18446744073709551616")],
    }
    for name, headers in malformed.items():
        path = DIAGNOSTIC_PREFIX + name
        add(name, {"path": path, "raw_requests": [wire(path, headers, method="POST")]},
            declared_scope="Actual host protocol rejection may occur before native allocation; absence is not a fabricated native phase.")
    for over in (False, True):
        count = 16 + int(over)
        name = "header_count_" + ("over_limit" if over else "at_limit")
        path = DIAGNOSTIC_PREFIX + name
        headers = [(f"X-Test-{index}", "v") for index in range(count - 2)]
        add(name, {"path": path, "raw_requests": [wire(path, headers)]},
            runtime_settings={"max_header_count": "16"}, declared_header_count=count)
        name = "total_header_bytes_" + ("over_limit" if over else "at_limit")
        path = DIAGNOSTIC_PREFIX + name
        # Actual mapper counts name+value only: Host13 + Connection15 + X-Pad5.
        value = "a" * (512 + int(over) - 33)
        add(name, {"path": path, "raw_requests": [wire(path, [("X-Pad", value)])]},
            runtime_settings={"max_total_header_bytes": "512"}, declared_header_bytes=512 + int(over))
    for name in ("keep_alive_requests_if_supported", "transport_keep_alive", "transport_sequential_requests",
                 "keepalive_allow_allow", "keepalive_allow_deny_allow"):
        denial = name not in ("transport_keep_alive", "keepalive_allow_allow")
        statuses = [200, 403, 200] if denial else [200, 200]
        requests = [wire(DIAGNOSTIC_PREFIX + name + f"/{index}",
            [("X-Modsec-Smoke", "block")] if status == 403 else (), close=False)
            for index, status in enumerate(statuses)]
        add(name, {"path": requests[-1]["path"], "raw_requests": requests},
            sequence_from_wire=True, expected_sequence_statuses=statuses, prove_connection_reuse=True)
    for name in ("event_metadata_truncation", "event_json_limit"):
        path = DIAGNOSTIC_PREFIX + name + "/" + "a" * 1536
        add(name, {"path": path, "headers": [["X-Modsec-Smoke", "log-only"]]},
            declared_non_sensitive_metadata_bytes=len(path), require_truncated_event=True)
    path = "/diagnostic/early-mapping-failure-cleanup"
    add("early_mapping_failure_cleanup", {"path": path, "raw_requests": [wire(path,
        [(f"X-Fault-{index}", "v") for index in range(15)])]}, runtime_settings={"max_header_count": "16"},
        declared_header_count=17, declared_fault_boundary="Productive request mapper rejects before Runtime transaction allocation.")
    add("transaction_begin_failure_cleanup", {"path": "/diagnostic/transaction-begin-failure-cleanup"},
        fault="request_headers_error", declared_fault_boundary="Explicit Runtime SDK-return boundary override during actual begin, after separately observed real SDK return1.")
    return {"route": "lighttpd-stock-native-control", "cases": planned}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("framework", "original", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--framework-sha", required=True)
    args = parser.parse_args()
    with i12_paths.new_text(args.output) as stream:
        json.dump(generate(args), stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
