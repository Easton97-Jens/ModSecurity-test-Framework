"""Separate opt-in registry and result completeness check for native H2 profiles.

Each registered adapter owns its real host, native evidence reader and cleanup.
This registry neither selects standard cases nor promotes capabilities.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter


SCENARIOS = (
    "allow", "phase1", "phase2", "phase3", "phase4_safe", "phase4_strict",
    "client_cancel", "upstream_reset",
)
ADAPTERS = {
    "apache_h2": ("apache", "connector_suite/adapters/apache/harness/apache_h2_acceptance.py"),
    "haproxy_htx_h2": ("haproxy-htx", "connector_suite/adapters/haproxy/harness/haproxy_h2_acceptance.py"),
    "haproxy_spop_htx_h2": ("haproxy-spoe-spop", "connector_suite/adapters/haproxy/harness/haproxy_spop_h2_acceptance.py"),
    "envoy_h2": ("envoy-ext-proc", "connector_suite/adapters/envoy/harness/envoy_h2_acceptance.py"),
}
CASES = {
    prefix + "_" + scenario: {
        "profile": profile, "adapter": adapter, "scenario": scenario, "protocol": "h2",
        "selection": "opt_in",
    }
    for prefix, (profile, adapter) in ADAPTERS.items()
    for scenario in SCENARIOS
}


def validate_results(results: list[dict]) -> dict:
    """Require exactly one terminal PASS per ID; host readers establish semantics."""
    if not isinstance(results, list) or not results:
        raise ValueError("missing or zero evaluated cases")
    if any(not isinstance(row, dict) or not isinstance(row.get("case_id"), str)
           for row in results):
        raise ValueError("invalid result identity")
    counts = Counter(row["case_id"] for row in results)
    if set(counts) != set(CASES) or any(count != 1 for count in counts.values()):
        raise ValueError("missing, duplicate or foreign case result")
    if any(row.get("status") != "PASS" for row in results):
        raise ValueError("every registered case requires an evaluated PASS")
    return {"status": "PASS", "registered": len(CASES), "evaluated": len(results),
            "profiles": dict(Counter(CASES[row["case_id"]]["profile"] for row in results))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print the closed opt-in registry")
    args = parser.parse_args()
    if not args.list:
        parser.error("--list is required; execute a profile through its listed adapter")
    print(json.dumps(CASES, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
