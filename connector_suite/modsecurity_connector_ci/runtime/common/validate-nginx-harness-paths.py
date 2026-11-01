#!/usr/bin/env python3
"""Fail closed unless NGINX harness output paths stay in verified runtime storage.

The root-required NGINX harness may create directories, change ownership and
permissions, and remove its own transient files.  Environment values are
therefore location hints, not write authority: every mutable path must be a
symlink-free child of one narrow verified runtime root accepted by the shared
runtime-path policy.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import os
import stat
import sys
from pathlib import Path


REPO_ROOT = connector_root()


from modsecurity_connector_ci.lib.runtime_path_utils import is_safe_runtime_root, runtime_artifact_path, verified_runtime_artifact_root


def parse_path_spec(values: list[str], option: str) -> tuple[str, Path]:
    if len(values) != 2:
        raise ValueError(f"{option} requires LABEL PATH")
    label, raw_path = values
    if not label:
        raise ValueError(f"{option} label must not be empty")
    return label, Path(raw_path)


def validate_direct_child(root: Path, label: str, candidate: Path) -> None:
    validated = runtime_artifact_path(root, candidate, label)
    if validated.parent != root:
        raise ValueError(f"{label} must be a direct child of its authorized parent")


def validate_existing_private_directory(label: str, candidate: Path) -> Path:
    """Validate a caller-supplied worker-visible projection parent without writing.

    A worker-visible docroot cannot be below the private `VERIFIED_RUN_ROOT`:
    the projection helper rejects that overlap deliberately.  Its parent is
    nevertheless a privileged output boundary, so it must already exist as a
    narrow, safe, current-user-owned runtime directory before this validator
    will authorize the helper's one fresh direct child.
    """

    if not candidate.is_absolute():
        raise ValueError(f"{label} must be absolute: {candidate}")
    normalized = Path(os.path.abspath(os.fspath(candidate)))
    if not is_safe_runtime_root(normalized):
        raise ValueError(f"{label} is unsafe for runtime writes: {normalized}")
    try:
        metadata = normalized.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} must be an existing private directory: {normalized}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be an existing non-symlink directory: {normalized}")
    # The shared verifier follows each existing component through no-follow
    # descriptors and verifies current-user ownership and non-writability.
    return verified_runtime_artifact_root(normalized)


def parse_direct_child_spec(values: list[str], option: str) -> tuple[str, str, str]:
    if len(values) != 3:
        raise ValueError(f"{option} requires LABEL PATH PARENT")
    return values[0], values[1], values[2]


def authorize_directories(
    verified_root: Path,
    raw_specs: list[list[str]],
    authorized: list[tuple[str, Path]],
) -> None:
    for raw_spec in raw_specs:
        label, candidate = parse_path_spec(raw_spec, "--directory")
        validated = runtime_artifact_path(verified_root, candidate, label)
        # The descriptor-safe helper has already verified every ancestor.
        # Creating the final directory only occurs below verified_root.
        verified_runtime_artifact_root(validated)
        authorized.append((label, validated))


def authorize_paths(
    verified_root: Path,
    raw_specs: list[list[str]],
    authorized: list[tuple[str, Path]],
) -> None:
    for raw_spec in raw_specs:
        label, candidate = parse_path_spec(raw_spec, "--path")
        authorized.append(
            (label, runtime_artifact_path(verified_root, candidate, label))
        )


def authorize_direct_children(
    verified_root: Path,
    raw_specs: list[list[str]],
    authorized: list[tuple[str, Path]],
) -> None:
    for raw_spec in raw_specs:
        label, raw_candidate, raw_parent = parse_direct_child_spec(
            raw_spec, "--direct-child"
        )
        parent = runtime_artifact_path(
            verified_root, Path(raw_parent), f"{label} parent"
        )
        verified_runtime_artifact_root(parent)
        validate_direct_child(parent, label, Path(raw_candidate))
        authorized.append((label, Path(raw_candidate)))


def authorize_existing_private_directories(
    raw_specs: list[list[str]],
    authorized: list[tuple[str, Path]],
) -> None:
    for raw_spec in raw_specs:
        label, candidate = parse_path_spec(raw_spec, "--existing-private-directory")
        authorized.append(
            (label, validate_existing_private_directory(label, candidate))
        )


def authorize_existing_direct_children(
    raw_specs: list[list[str]],
    authorized: list[tuple[str, Path]],
) -> None:
    for raw_spec in raw_specs:
        label, raw_candidate, raw_parent = parse_direct_child_spec(
            raw_spec, "--existing-direct-child"
        )
        parent = validate_existing_private_directory(
            f"{label} parent", Path(raw_parent)
        )
        candidate = Path(raw_candidate)
        validate_direct_child(parent, label, candidate)
        if candidate.exists() or candidate.is_symlink():
            raise ValueError(f"{label} must be a fresh non-symlink child")
        authorized.append((label, candidate))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified-run-root", required=True, type=Path)
    parser.add_argument(
        "--directory",
        action="append",
        nargs=2,
        default=[],
        metavar=("LABEL", "PATH"),
        help="authorize and create a private output directory below the verified root",
    )
    parser.add_argument(
        "--path",
        action="append",
        nargs=2,
        default=[],
        metavar=("LABEL", "PATH"),
        help="authorize a not-yet-created path below the verified root",
    )
    parser.add_argument(
        "--direct-child",
        action="append",
        nargs=3,
        default=[],
        metavar=("LABEL", "PATH", "PARENT"),
        help="authorize a path and require its canonical parent to be PARENT",
    )
    parser.add_argument(
        "--existing-private-directory",
        action="append",
        nargs=2,
        default=[],
        metavar=("LABEL", "PATH"),
        help="authorize an existing worker-visible private directory without creating it",
    )
    parser.add_argument(
        "--existing-direct-child",
        action="append",
        nargs=3,
        default=[],
        metavar=("LABEL", "PATH", "PARENT"),
        help="authorize one fresh direct child below an existing private directory",
    )
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        verified_root = verified_runtime_artifact_root(args.verified_run_root)
        authorized: list[tuple[str, Path]] = []
        authorize_directories(verified_root, args.directory, authorized)
        authorize_paths(verified_root, args.path, authorized)
        authorize_direct_children(verified_root, args.direct_child, authorized)
        authorize_existing_private_directories(
            args.existing_private_directory, authorized
        )
        authorize_existing_direct_children(args.existing_direct_child, authorized)
    except (OSError, ValueError) as exc:
        print(f"nginx harness path authority rejected: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        for label, path in authorized:
            print(f"{label}={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
