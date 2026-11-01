#!/usr/bin/env python3
"""Write narrow host-result rows for the two causal Phase-4 capabilities."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any




from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, runtime_artifact_path
from modsecurity_connector_ci.lib.first_byte_binding import verify_binding


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON object required")
    return value


def has_phase4_rule(path: Path, transaction_id: str | None = None) -> bool:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        if transaction_id is not None and record.get("transaction_id") != transaction_id:
            continue
        if str(record.get("rule_id") or "") == "1100301" and str(record.get("phase") or "").replace("-", "_") in {"4", "response_body", "phase4"}:
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True, choices=("apache", "nginx"))
    parser.add_argument("--phase4-log", required=True, type=Path)
    parser.add_argument("--first-byte-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    runtime_root = prepare_verified_runtime_artifact_root()
    phase4_log = runtime_artifact_path(
        runtime_root, args.phase4_log, "Phase-4 log", must_exist=True
    )
    first_byte_evidence = runtime_artifact_path(
        runtime_root, args.first_byte_evidence, "first-byte evidence", must_exist=True
    )
    output = runtime_artifact_path(runtime_root, args.output, "output")
    evidence = load_object(first_byte_evidence)
    required = {
        "evidence_type": "synchronized_first_byte",
        "evidence_origin": "real_host",
        "promotion_eligible": True,
        "outcome": "PASS",
        "body_payload_persisted": False,
        "first_byte_before_response_end": True,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
    }
    if any(evidence.get(key) != expected for key, expected in required.items()):
        raise ValueError("first-byte evidence is not a successful real-host no-buffer observation")
    binding_fields: dict[str, Any] = {}
    if args.connector == "nginx":
        binding_path = runtime_artifact_path(
            runtime_root, Path(str(first_byte_evidence) + ".binding.json"),
            "first-byte binding", must_exist=True,
        )
        binding = load_object(binding_path)
        event = verify_binding(binding, phase4_log, first_byte_evidence, runtime_root)
        binding_fields = {"first_byte_binding_path": str(binding_path),
                          "transaction_id": event["transaction_id"]}
    if not has_phase4_rule(phase4_log, binding_fields.get("transaction_id")):
        raise ValueError("Phase-4 rule 1100301 was not observed for the bound host transaction")
    rows = [
        {
            "case_id": case_id,
            "status": "PASS",
            "live_executed": True,
            "actual_status": 200,
            "observed_rule_ids": [1100301],
            "connector_phase4_log_path": str(phase4_log),
            "first_byte_evidence_path": str(first_byte_evidence),
            **binding_fields,
            "reason": "real host synchronized upstream barrier; payload-free metadata only",
        }
        for case_id in (
            "phase4_rule_observed",
            "phase4_first_byte_before_response_end",
            "phase4_no_full_response_buffering",
        )
    ]
    output.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
