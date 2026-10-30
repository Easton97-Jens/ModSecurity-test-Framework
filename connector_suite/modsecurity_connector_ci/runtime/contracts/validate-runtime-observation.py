#!/usr/bin/env python3
"""Command-line entry point for strict canonical runtime-observation validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from modsecurity_connector_ci.runtime.contracts.runtime_observation import ObservationInputError, load_runtime_observation_file, validate_runtime_observation


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        help="private root containing --observation and its relative evidence files",
    )
    parser.add_argument("--connector", required=True)
    parser.add_argument("--adapter-id", required=True)
    parser.add_argument("--integration-mode", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--framework-sha", required=True)
    parser.add_argument("--mrts-sha", required=True)
    parser.add_argument("--policy", choices=("strict", "partial"), default="strict")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    observation_path = arguments.observation.absolute()
    evidence_root = (arguments.evidence_root or observation_path.parent).absolute()
    try:
        observation = load_runtime_observation_file(observation_path, evidence_root)
        result = validate_runtime_observation(
            observation,
            {
                "connector": arguments.connector,
                "adapter_id": arguments.adapter_id,
                "integration_mode": arguments.integration_mode,
                "profile": arguments.profile,
                "run_id": arguments.run_id,
                "parent_sha": arguments.parent_sha,
                "framework_sha": arguments.framework_sha,
                "mrts_sha": arguments.mrts_sha,
            },
            {"name": arguments.policy, "evidence_root": evidence_root},
        )
    except (ObservationInputError, OSError, RecursionError, TypeError, ValueError) as exc:
        result = {
            "schema_version": 1,
            "result_type": "runtime_observation_validation",
            "status": "VALIDATION_FAILED",
            "validation_status": "VALIDATION_FAILED",
            "policy": arguments.policy,
            "failure_count": 1,
            "incomplete_count": 0,
            "errors": ["unsafe or malformed runtime observation input: " + " ".join(str(exc).split())[:512]],
            "identity": {},
            "evidence_disposition": "not_validated",
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
