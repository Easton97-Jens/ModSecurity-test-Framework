#!/usr/bin/env python3
"""Invoke the closed five-connector catalog tool through a fixed argv vector."""

from __future__ import annotations

import os
import sys

from ci.checks.catalog import five_connectors_with_crs_no_mrts as contract


def _environment_value(name: str, *, required: bool = False) -> str:
    """Read one Make-exported value without asking a shell to parse it."""
    value = os.environ.get(name, "").replace("$$", "$")
    if required and not value:
        raise ValueError(f"{name} is required")
    return value


def argument_vector(command: str) -> list[str]:
    """Build the fixed catalog argv for one supported Make target command."""
    source_root = _environment_value("SOURCE_ROOT", required=True)
    if command == "verify-fixture":
        return ["verify-fixture", "--source-root", source_root]
    evidence_root = _environment_value(
        "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_EVIDENCE_ROOT", required=True
    )
    run_id = _environment_value(
        "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_RUN_ID", required=True
    )
    if command == "validate":
        connector = _environment_value(
            "FIVE_CONNECTORS_WITH_CRS_NO_MRTS_CONNECTOR", required=True
        )
        return [
            "validate",
            "--evidence-root",
            evidence_root,
            "--source-root",
            source_root,
            "--connector",
            connector,
            "--run-id",
            run_id,
        ]
    if command == "aggregate":
        return [
            "aggregate",
            "--evidence-root",
            evidence_root,
            "--source-root",
            source_root,
            "--run-id",
            run_id,
        ]
    raise ValueError(f"unsupported five-connector command: {command}")


def main(argv: list[str] | None = None) -> int:
    """Reject dynamic commands and delegate only fixed arguments to the catalog tool."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print(
            "usage: run-five-connectors-with-crs-no-mrts.py <command>", file=sys.stderr
        )
        return 2
    try:
        return contract.main(argument_vector(arguments[0]))
    except ValueError as error:
        print(f"five-connector contract configuration error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
