#!/usr/bin/env python3
"""Relocate Traefik's fixed runtime outputs into the canonical raw run.

The Traefik runtime intentionally writes beneath its private build root.  The
No-CRS collector intentionally accepts source artifacts only from the separate
per-run raw root.  This narrow bridge moves exactly the two fixed producer
files after the host stage has stopped; it never adds another collector trust
root or accepts caller-selected artifact paths.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import os
from pathlib import Path
import sys


CI_LIB = source_path('ci') / "lib"


from modsecurity_connector_ci.lib.runtime_path_utils import is_under, move_runtime_artifact_atomic, prepare_verified_runtime_artifact_root, runtime_artifact_path


TRAEFIK_RUNTIME_DIRECTORY = Path("traefik-runtime")
TRAEFIK_ARTIFACTS = (
    (Path("result.json"), Path("traefik-source") / "result.json", "Traefik result"),
    (
        Path("logs") / "events.jsonl",
        Path("traefik-source") / "events.jsonl",
        "Traefik events",
    ),
)


def optional_source_exists(path: Path) -> bool:
    """Report existence without following a final symlink.

    An existing symlink is deliberately treated as present so the checked
    no-follow relocation rejects it.  Only genuine absence remains absence.
    """

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def stage_traefik_runtime_artifacts(build_root_value: Path, raw_root_value: Path) -> tuple[Path, ...]:
    """Move the fixed Traefik result and event stream into the raw run."""

    build_root = prepare_verified_runtime_artifact_root(build_root_value)
    raw_root = prepare_verified_runtime_artifact_root(raw_root_value)
    if (
        build_root == raw_root
        or is_under(build_root, raw_root)
        or is_under(raw_root, build_root)
    ):
        raise ValueError("Traefik build and raw roots must remain separate")
    runtime_root = build_root / TRAEFIK_RUNTIME_DIRECTORY

    if not optional_source_exists(runtime_root):
        return ()
    # Validate the fixed source directory even when an expected leaf is absent:
    # a dangling directory symlink must not silently look like no evidence.
    runtime_artifact_path(
        build_root,
        runtime_root / ".stage-probe",
        "Traefik runtime artifact directory",
    )
    logs_root = runtime_root / "logs"
    if optional_source_exists(logs_root):
        runtime_artifact_path(
            build_root,
            logs_root / ".stage-probe",
            "Traefik runtime event directory",
        )

    staged: list[Path] = []
    for source_relative, destination_relative, label in TRAEFIK_ARTIFACTS:
        source = runtime_root / source_relative
        if not optional_source_exists(source):
            continue
        staged.append(
            move_runtime_artifact_atomic(
                build_root,
                source,
                raw_root,
                raw_root / destination_relative,
                label,
            )
        )
    return tuple(staged)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--raw-root", required=True, type=Path)
    return parser


def main() -> int:
    parser = argument_parser()
    args = parser.parse_args()
    try:
        stage_traefik_runtime_artifacts(args.build_root, args.raw_root)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
