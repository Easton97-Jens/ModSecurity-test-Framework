#!/usr/bin/env python3
"""Stage and verify the payload-safe full-runtime evidence artifact.

The strict report-evidence gate remains the authority for runtime correctness.
This tool snapshots its fixed structured allowlist using descriptor-relative
reads, then compares that snapshot with a final rerun of the strict gate's
inputs before a hosted artifact action can reopen the staged path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.


from modsecurity_connector_ci.lib.verified_full_matrix_receipt import AggregateReceiptError, STAGED_EVIDENCE_FILE_COUNT, StagedEvidence, stage_verified_full_matrix_evidence, verify_staged_full_matrix_evidence


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    stage = commands.add_parser("stage", help="create one fresh private evidence snapshot")
    stage.add_argument("--connector-root", required=True)
    stage.add_argument("--build-root", required=True)
    stage.add_argument("--stage-root", required=True)

    verify = commands.add_parser("verify", help="compare a staged snapshot with current strict-gate inputs")
    verify.add_argument("--connector-root", required=True)
    verify.add_argument("--build-root", required=True)
    verify.add_argument("--stage-root", required=True)
    return result


def evidence_summary(evidence: StagedEvidence) -> str:
    return json.dumps(
        {
            "stage_root": str(evidence.stage_root),
            "verified_run_id": evidence.verified_run_id,
            "files": [
                {"path": item.relative_path, "sha256": item.sha256, "bytes": item.bytes}
                for item in evidence.files
            ],
        },
        sort_keys=True,
    )


def main() -> int:
    args = parser().parse_args()
    connector_root = Path(args.connector_root)
    build_root = Path(args.build_root)
    try:
        if args.command == "stage":
            evidence = stage_verified_full_matrix_evidence(
                connector_root=connector_root,
                build_root=build_root,
                stage_root=Path(args.stage_root),
            )
        else:
            evidence = verify_staged_full_matrix_evidence(
                connector_root=connector_root,
                build_root=build_root,
                stage_root=Path(args.stage_root),
            )
    except AggregateReceiptError as exc:
        print(f"stage-verified-full-matrix-evidence: FAIL: {exc}", file=sys.stderr)
        return 1
    if len(evidence.files) != STAGED_EVIDENCE_FILE_COUNT:
        print("stage-verified-full-matrix-evidence: FAIL: unexpected staged evidence count", file=sys.stderr)
        return 1
    print(evidence_summary(evidence))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
