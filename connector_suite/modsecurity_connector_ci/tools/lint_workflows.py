#!/usr/bin/env python3
"""Lint original workflows with compatibility for GitHub self-repository uses.

Actionlint 1.7.12 predates GitHub's $/ syntax. Translate only those uses values
to its equivalent local-path syntax in memory; security audits read originals.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess

import yaml
from yaml.tokens import KeyToken, ScalarToken, ValueToken

PATH_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$", re.ASCII)
ROOT = connector_root()


def actionlint_source(source: str) -> str:
    """Normalize safe self-repository references without changing other text."""

    try:
        tokens = list(yaml.scan(source))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid workflow YAML: {exc}") from exc
    replacements: list[int] = []
    for index in range(1, len(tokens) - 2):
        key, separator, value = tokens[index:index + 3]
        if not (
            isinstance(tokens[index - 1], KeyToken)
            and isinstance(key, ScalarToken) and key.value == "uses"
            and isinstance(separator, ValueToken)
            and isinstance(value, ScalarToken) and value.value.startswith("$/")
        ):
            continue
        reference = value.value
        parts = reference[2:].split("/")
        if any(
            part in {"", ".", ".."} or PATH_COMPONENT.fullmatch(part) is None
            for part in parts
        ):
            raise ValueError(f"unsafe self-repository reference: {reference!r}")
        start, end = value.start_mark.index, value.end_mark.index
        relative = source[start:end].find(reference)
        if relative < 0:
            raise ValueError("self-repository uses must contain its literal path")
        replacements.append(start + relative)
    for offset in reversed(replacements):
        source = source[:offset] + "." + source[offset + 1:]
    return source


def checked_path(path: Path, *, directory: bool = False, owner: int | None = None) -> Path:
    """Reject traversal, symlink ancestors and inappropriate file identities."""

    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("lint paths must be absolute and traversal-free")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ValueError("lint paths must not contain symlinks")
    identity = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(identity.st_mode):
        raise ValueError("lint path has an unexpected file type")
    if owner is not None and (
        identity.st_uid != owner or identity.st_mode & 0o022
    ):
        raise ValueError("lint tool staging must be owned and not group/world writable")
    return path


def reviewed_actionlint(candidate_tree: bool) -> Path:
    """Use only the fixed checksum-fetcher locations for the selected mode."""

    runner_temp = checked_path(
        Path(os.environ.get("RUNNER_TEMP", "")), directory=True, owner=os.geteuid()
    )
    if candidate_tree:
        checked_path(ROOT, directory=True, owner=os.geteuid())
        if ROOT == runner_temp or not ROOT.is_relative_to(runner_temp):
            raise ValueError("candidate lint requires a private tree below RUNNER_TEMP")
        executable = source_path('.candidate-security-tools/actionlint/actionlint', root=ROOT)
    else:
        executable = runner_temp / "security-tools/actionlint"
    for directory in (executable.parent, executable.parent.parent):
        checked_path(directory, directory=True, owner=os.geteuid())
    checked_path(executable, owner=os.geteuid())
    if not executable.stat().st_mode & 0o111:
        raise ValueError("reviewed actionlint is not executable")
    return executable


def workflow_paths() -> list[Path]:
    """Discover only repository workflows and the two fixed permission fixtures."""

    directory = checked_path(source_path('.github/workflows', root=ROOT), directory=True)
    paths = sorted(path for path in directory.rglob("*") if path.suffix in {".yml", ".yaml"})
    if not paths:
        raise ValueError("no repository workflows found")
    paths.extend(source_path('ci/fixtures/workflow-permission-contract', root=ROOT) / name for name in ("safe.yml", "unsafe.yml"))
    return [checked_path(path) for path in paths]


def lint(*, candidate_tree: bool = False) -> int:
    """Check fixed workflows with the reviewed tool, preserving original files."""

    actionlint = str(reviewed_actionlint(candidate_tree))
    shellcheck = ""
    system_shellcheck = Path("/usr/bin/shellcheck")
    if system_shellcheck.exists() or system_shellcheck.is_symlink():
        shellcheck = str(checked_path(system_shellcheck, owner=0))
    status = 0
    for workflow in workflow_paths():
        source = actionlint_source(workflow.read_text(encoding="utf-8"))
        result = subprocess.run(
            [actionlint, f"-shellcheck={shellcheck}", "-stdin-filename", str(workflow), "-"],
            input=source,
            text=True,
            check=False,
            timeout=120,
        )
        if result.returncode:
            status = result.returncode if result.returncode > 0 else 1
    return status


def main() -> int:
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-tree", action="store_true")
    parser.add_argument("--candidate-root", type=Path)
    args = parser.parse_args()
    try:
        if args.candidate_root is not None:
            if not args.candidate_tree:
                raise ValueError("--candidate-root requires --candidate-tree")
            candidate = checked_path(args.candidate_root, directory=True, owner=os.geteuid())
            runner_temp = checked_path(Path(os.environ.get("RUNNER_TEMP", "")),
                                       directory=True, owner=os.geteuid())
            if candidate == runner_temp or not candidate.is_relative_to(runner_temp):
                raise ValueError("candidate lint requires a private tree below RUNNER_TEMP")
            ROOT = candidate
        return lint(candidate_tree=args.candidate_tree)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"workflow lint failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
